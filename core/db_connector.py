"""
core/db_connector.py — Provider-agnostic database abstraction.

Supports:
  - OpenSearch  (via opensearch-py)
  - Elasticsearch (via elasticsearch-py)

Abstracts:
  - Standard search / index / delete
  - Anomaly Detection findings poll
  - k-NN vector storage and similarity search
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Optional
from datetime import datetime, timezone

from core.config import Config

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Abstract base
# ──────────────────────────────────────────────────────────────────────────────

class BaseDBConnector(ABC):
    """Common interface every DB backend must implement."""

    @abstractmethod
    def search(self, index: str, query: dict, size: int = 100) -> list[dict]:
        """Execute a search query and return hits as dicts."""

    @abstractmethod
    def index_document(self, index: str, doc_id: str, body: dict) -> dict:
        """Index a single document."""

    @abstractmethod
    def bulk_index(self, index: str, documents: list[dict]) -> dict:
        """Bulk-index a list of documents (each must have a '_id' key)."""

    @abstractmethod
    def get_anomaly_findings(
        self,
        detector_id: str,
        from_epoch_ms: Optional[int] = None,
        size: int = 50,
    ) -> list[dict]:
        """Return anomaly detection findings from the DB."""

    @abstractmethod
    def knn_search(
        self,
        index: str,
        vector: list[float],
        k: int = 5,
        filters: Optional[dict] = None,
    ) -> list[dict]:
        """k-NN approximate nearest-neighbor search."""

    @abstractmethod
    def ensure_index(
        self,
        index: str,
        mappings: dict,
        settings: Optional[dict] = None,
    ) -> None:
        """Create index if it does not exist."""


# ──────────────────────────────────────────────────────────────────────────────
# OpenSearch / Elasticsearch implementation
# ──────────────────────────────────────────────────────────────────────────────

class OpenSearchConnector(BaseDBConnector):
    """
    Works against OpenSearch 2.x (and Elasticsearch 8.x with minor
    path differences — governed by `provider` config key).
    """

    def __init__(self, client: Any = None) -> None:
        """
        Pass a pre-built client for testing, or leave None for
        auto-construction from config.yaml.
        """
        self.cfg = Config()
        self._client = client or self._build_client()
        self._provider = self.cfg.get("db", "provider", default="opensearch")
        # Load index configuration
        self.logs_index = self.cfg.get("db", "logs_index", default="securityclaw-logs")
        self.anomaly_index = self.cfg.get("db", "anomaly_index", default="securityclaw-anomalies")
        self.vector_index = self.cfg.get("db", "vector_index", default="securityclaw-vectors")

    def _build_client(self) -> Any:
        provider = self.cfg.get("db", "provider", default="opensearch")
        host = self.cfg.get("db", "host", default="localhost")
        port = int(self.cfg.get("db", "port", default=9200))
        use_ssl = self.cfg.get("db", "use_ssl", default=False)
        verify = self.cfg.get("db", "verify_certs", default=False)
        user = self.cfg.get("db", "username", default="")
        password = self.cfg.get("db", "password", default="")

        conn_args = dict(
            hosts=[{"host": host, "port": port}],
            use_ssl=use_ssl,
            verify_certs=verify,
            ssl_show_warn=False,
        )
        if user and password:
            conn_args["http_auth"] = (user, password)

        if provider == "elasticsearch":
            from elasticsearch import Elasticsearch
            return Elasticsearch(**conn_args)

        from opensearchpy import OpenSearch
        return OpenSearch(**conn_args)

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(self, index: str, query: dict, size: int = 100) -> list[dict]:
        """Execute search with automatic recovery from 400 errors."""
        return self._search_with_retry(index, query, size)

    def _search_with_retry(self, index: str, query: dict, size: int, attempt: int = 0, max_retries: int = 3) -> list[dict]:
        """
        Execute search with fallback strategies for malformed queries.
        
        Retry strategies:
        1. Original query
        2. Remove complex bool clauses (should, must)
        3. Use only timestamp filter with match-all
        4. Use match-all without any filters
        """
        if attempt >= max_retries:
            logger.error("search(%s) failed after %d retry attempts", index, max_retries)
            return []
        
        try:
            resp = self._client.search(index=index, body=query, size=size)
            if attempt > 0:
                logger.info("search(%s) recovered on attempt %d with fallback strategy", index, attempt + 1)
            return [hit["_source"] for hit in resp["hits"]["hits"]]
        
        except Exception as exc:
            error_str = str(exc)
            
            # Check if it's a 400 error (query syntax/parsing error)
            if "400" in error_str or "failed to create query" in error_str or "RequestError" in error_str:
                logger.warning("search(%s) attempt %d failed with query error: %s", 
                             index, attempt + 1, error_str)
                
                # Get fallback query based on attempt number
                fallback_query = self._get_fallback_query(query, attempt)
                
                if fallback_query is not None:
                    logger.info("search(%s) attempting recovery #%d with simplified query", index, attempt + 2)
                    return self._search_with_retry(index, fallback_query, size, attempt + 1, max_retries)
                else:
                    logger.error("search(%s) no more fallback strategies available after attempt %d", 
                               index, attempt + 1)
                    return []
            else:
                # Non-400 errors are not retried
                logger.error("search(%s) failed with non-query error: %s", index, exc)
                return []

    def _get_fallback_query(self, query: dict, attempt: int) -> Optional[dict]:
        """
        Generate increasingly simple fallback queries to recover from malformed queries.
        
        Strategies:
        Attempt 0: Original failed, try removing complex clauses (should, must, nested bool)
        Attempt 1: Time-range filter only with match_all query  
        Attempt 2+: Simple match-all query
        """
        import copy
        
        if attempt == 0:
            # Try to simplify complex bool queries by removing problematic should/must clauses
            simplified = copy.deepcopy(query)
            
            if "query" in simplified:
                try:
                    query_part = simplified["query"]
                    
                    # If it's a bool query, strip down to essential parts
                    if isinstance(query_part, dict) and "bool" in query_part:
                        bool_q = query_part["bool"]
                        
                        # Remove the most problematic clauses
                        if "should" in bool_q:
                            logger.debug("Attempt 1 (simplify): Removing 'should' clauses")
                            del bool_q["should"]
                        if "minimum_should_match" in bool_q:
                            del bool_q["minimum_should_match"]
                        if "must_not" in bool_q:
                            logger.debug("Attempt 1 (simplify): Removing 'must_not' clauses")
                            del bool_q["must_not"]
                        
                        # If we still have must or filter, keep them
                        # If we removed everything, still return it for next attempt
                        return simplified
                except Exception as e:
                    logger.debug("Simplification failed: %s", e)
            
            # If not a bool query, return as-is for next attempt
            return simplified
        
        elif attempt == 1:
            # Use absolutely minimal query with just time range
            try:
                # Extract time range if present
                time_range_filter = None
                
                if "query" in query and isinstance(query["query"], dict):
                    q = query["query"]
                    if "bool" in q and "filter" in q["bool"]:
                        filters = q["bool"]["filter"]
                        # Find range filter
                        if isinstance(filters, list):
                            for f in filters:
                                if isinstance(f, dict) and "range" in f:
                                    time_range_filter = f
                                    break
                        elif isinstance(filters, dict) and "range" in filters:
                            time_range_filter = filters
                
                # Build simple query with just time filter
                fallback = {
                    "query": {"match_all": {}},
                    "size": query.get("size", 100)
                }
                
                if time_range_filter:
                    # Add time filter to bool query
                    fallback["query"] = {
                        "bool": {
                            "filter": [time_range_filter]
                        }
                    }
                
                logger.debug("Attempt 2 (time-range): Using minimal query (match_all + time filter)")
                return fallback
                
            except Exception as e:
                logger.debug("Time-range fallback failed: %s", e)
                return None
        
        elif attempt >= 2:
            # Last resort: absolute minimum - match all with size limit
            logger.debug("Attempt 3+ (bare match_all): Using simplest possible query")
            return {
                "query": {"match_all": {}},
                "size": query.get("size", 100)
            }
        
        return None

    def get_document(self, index: str, doc_id: str) -> Optional[dict]:
        try:
            resp = self._client.get(index=index, id=doc_id)
            return resp["_source"]
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def index_document(self, index: str, doc_id: str, body: dict) -> dict:
        try:
            return self._client.index(index=index, id=doc_id, body=body, refresh="wait_for")
        except Exception as exc:
            logger.error("index_document(%s, %s) failed: %s", index, doc_id, exc)
            raise

    def bulk_index(self, index: str, documents: list[dict]) -> dict:
        from opensearchpy.helpers import bulk as os_bulk
        from elasticsearch.helpers import bulk as es_bulk

        actions = [
            {
                "_index": index,
                "_id": doc.get("_id", doc.get("id")),
                "_source": {k: v for k, v in doc.items() if k not in ("_id",)},
            }
            for doc in documents
        ]
        try:
            if self._provider == "elasticsearch":
                success, errors = es_bulk(self._client, actions)
            else:
                success, errors = os_bulk(self._client, actions)
            return {"success": success, "errors": errors}
        except Exception as exc:
            logger.error("bulk_index(%s) failed: %s", index, exc)
            raise

    # ------------------------------------------------------------------
    # Anomaly Detection
    # ------------------------------------------------------------------

    def get_anomaly_findings(
        self,
        detector_id: str,
        from_epoch_ms: Optional[int] = None,
        size: int = 50,
    ) -> list[dict]:
        """
        Query anomaly detection findings.
        
        For OpenSearch: Uses the configured anomaly_index (defaults to OpenSearch's
        built-in .opendistro-anomaly-results* pattern, but can be overridden).
        
        Args:
            detector_id: The AD detector ID
            from_epoch_ms: Optional cursor for incremental polling
            size: Max results to return
        """
        # Use configured anomaly index, or OpenSearch's default pattern
        ad_index = self.anomaly_index
        if ad_index == "securityclaw-anomalies":
            # If using default, check for OpenSearch AD results index
            ad_index = ".opendistro-anomaly-results*"
        
        must_clauses: list[dict] = [
            {"term": {"detector_id": detector_id}}
        ]
        if from_epoch_ms:
            must_clauses.append(
                {"range": {"data_end_time": {"gte": from_epoch_ms}}}
            )

        query = {
            "query": {"bool": {"must": must_clauses}},
            "sort": [{"data_end_time": {"order": "desc"}}],
        }
        return self.search(ad_index, query, size=size)

    # ------------------------------------------------------------------
    # k-NN (vector) search
    # ------------------------------------------------------------------

    def knn_search(
        self,
        index: str,
        vector: list[float],
        k: int = 5,
        filters: Optional[dict] = None,
    ) -> list[dict]:
        """
        k-NN approximate nearest-neighbor search.
        Handles filters at the query level (not in KNN block) for compatibility with NMSLIB.
        """
        knn_body: dict = {
            "vector": vector,
            "k": k,
        }
        # Note: NMSLIB doesn't support filters inside the KNN block,
        # so we apply filters at the outer query level instead

        query: dict
        if filters:
            # Build a bool query with both KNN and filter
            query = {
                "bool": {
                    "must": {
                        "knn": {"embedding": knn_body}
                    },
                    "filter": filters
                }
            }
        else:
            # Simple KNN query without filters
            query = {"knn": {"embedding": knn_body}}
        
        try:
            resp = self._client.search(index=index, body={"query": query}, size=k)
            return [
                {**hit["_source"], "_score": hit.get("_score")}
                for hit in resp["hits"]["hits"]
            ]
        except Exception as exc:
            logger.error("knn_search(%s) failed: %s", index, exc)
            return []

    # ------------------------------------------------------------------
    # Index management
    # ------------------------------------------------------------------

    def ensure_index(
        self,
        index: str,
        mappings: dict,
        settings: Optional[dict] = None,
    ) -> None:
        try:
            if not self._client.indices.exists(index=index):
                body: dict = {"mappings": mappings}
                if settings:
                    body["settings"] = settings
                self._client.indices.create(index=index, body=body)
                logger.info("Created index: %s", index)
        except Exception as exc:
            logger.warning("ensure_index(%s): %s", index, exc)

    # ------------------------------------------------------------------
    # Vector index bootstrap
    # ------------------------------------------------------------------

    def ensure_vector_index(self, index: str, dims: int = 768) -> None:
        """Create a k-NN enabled index for embedding storage.
        
        Default dims=768 is a reasonable default, but callers should
        explicitly pass dims from their LLM provider's embedding_dimension.
        """
        settings = {
            "index": {
                "knn": True,
                "knn.algo_param.ef_search": 100,
            }
        }
        mappings = {
            "properties": {
                "embedding": {
                    "type": "knn_vector",
                    "dimension": dims,
                    "method": {
                        "name": "hnsw",
                        "space_type": "l2",
                        "engine": "nmslib",
                    },
                },
                "text": {"type": "text"},
                "category": {"type": "keyword"},
                "source": {"type": "keyword"},
                "timestamp": {"type": "date"},
            }
        }
        self.ensure_index(index, mappings, settings)
