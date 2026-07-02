"""
api/services/search_service.py — External web search and scraping service.

Primary flow:
  - query Wikipedia OpenSearch for top results
  - extract the top N result URLs
  - fetch page content directly for top results
  - cache the combined result set by normalized query

Fallback flow:
  - if Wikipedia search fails, try DuckDuckGo HTML scraping
  - if page text cannot be extracted, return the result metadata only
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime
from html.parser import HTMLParser
from typing import Any, Dict, List

import httpx

from ..cache.cache_manager import CacheManager
from ..schemas import SearchResponse, SearchResultItem

logger = logging.getLogger("hollowpurple.search")

WIKIPEDIA_OPENSEARCH = "https://en.wikipedia.org/w/api.php"
DUCKDUCKGO_HTML = "https://duckduckgo.com/html/"
DEFAULT_CACHE_TTL = int(os.getenv("HP_WEBSEARCH_CACHE_TTL_SECONDS", "86400"))
HTTP_TIMEOUT = 15.0
MAX_PAGE_TEXT_CHARS = 20000


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._texts: List[str] = []
        self._skip_stack: List[str] = []
        self._skip_tags = {
            "script",
            "style",
            "noscript",
            "header",
            "footer",
            "svg",
            "iframe",
            "canvas",
            "link",
            "meta",
            "nav",
        }

    def handle_starttag(self, tag: str, attrs: List[Any]) -> None:
        if tag in self._skip_tags:
            self._skip_stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if self._skip_stack and self._skip_stack[-1] == tag:
            self._skip_stack.pop()

    def handle_data(self, data: str) -> None:
        if self._skip_stack:
            return
        text = data.strip()
        if text:
            self._texts.append(text)

    def handle_comment(self, data: str) -> None:
        return

    def get_text(self) -> str:
        return " ".join(self._texts)


class _DuckDuckGoResultExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.results: List[Dict[str, str]] = []
        self._current: Dict[str, str] = {}
        self._collecting = False

    def handle_starttag(self, tag: str, attrs: List[Any]) -> None:
        if tag != "a":
            return
        attrs_dict = dict(attrs)
        class_name = attrs_dict.get("class", "")
        if "result__a" in class_name:
            href = attrs_dict.get("href", "")
            if href:
                self._current = {"href": href, "title": ""}
                self._collecting = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._collecting:
            if self._current.get("href"):
                self.results.append({
                    "href": self._current["href"],
                    "title": self._current["title"].strip(),
                })
            self._current = {}
            self._collecting = False

    def handle_data(self, data: str) -> None:
        if self._collecting:
            self._current["title"] += data


class SearchService:
    def __init__(self) -> None:
        self._cache = CacheManager(ttl=DEFAULT_CACHE_TTL, max_size=500)

    @staticmethod
    def _normalize_query(query: str) -> str:
        return " ".join(query.strip().lower().split())

    @staticmethod
    def _clean_text(text: str) -> str:
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    @staticmethod
    def _truncate_text(text: str) -> str:
        if len(text) <= MAX_PAGE_TEXT_CHARS:
            return text
        return text[:MAX_PAGE_TEXT_CHARS].strip() + " …"

    async def _fetch_json(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={
            "User-Agent": "HollowPurpleWebSearch/1.0",
            "Accept": "application/json",
        }) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            return response.json()

    async def _fetch_page_text(self, url: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HollowPurpleBot/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }, follow_redirects=True) as client:
                response = await client.get(url)

            response.raise_for_status()
            content_type = response.headers.get("content-type", "")
            if "html" not in content_type.lower():
                return ""
            parser = _HTMLTextExtractor()
            parser.feed(response.text)
            return self._truncate_text(self._clean_text(parser.get_text()))
        except Exception as exc:  # pragma: no cover
            logger.warning("Failed scraping page %s: %s", url, exc)
            return ""

    async def _search_wikipedia(self, query: str, limit: int) -> List[Dict[str, str]]:
        try:
            response = await self._fetch_json(WIKIPEDIA_OPENSEARCH, {
                "action": "opensearch",
                "search": query,
                "limit": limit,
                "namespace": 0,
                "format": "json",
            })
            if len(response) < 4:
                return []
            titles = response[1] if isinstance(response[1], list) else []
            snippets = response[2] if isinstance(response[2], list) else []
            urls = response[3] if isinstance(response[3], list) else []
            return [
                {
                    "title": titles[i] if i < len(titles) else url,
                    "url": url,
                    "snippet": snippets[i] if i < len(snippets) else "",
                }
                for i, url in enumerate(urls[:limit])
                if isinstance(url, str) and url
            ]
        except Exception as exc:  # pragma: no cover
            logger.warning("Wikipedia fallback request failed for query %s: %s", query, exc)
            return []

    async def _search_duckduckgo(self, query: str, limit: int) -> List[Dict[str, str]]:
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={
                "User-Agent": "HollowPurpleWebSearch/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }) as client:
                response = await client.get(DUCKDUCKGO_HTML, params={"q": query})
                response.raise_for_status()
                extractor = _DuckDuckGoResultExtractor()
                extractor.feed(response.text)
                return [
                    {"title": item["title"], "url": item["href"], "snippet": ""}
                    for item in extractor.results[:limit]
                ]
        except Exception as exc:  # pragma: no cover
            logger.warning("DuckDuckGo search failed for query %s: %s", query, exc)
            return []

    @staticmethod
    def _classify_query(query: str) -> str:
        normalized = query.strip().lower()
        if not normalized:
            return "fact"
        factual_triggers = ["what", "who", "when", "where", "how many", "how much", "define", "definition", "meaning"]
        if any(normalized.startswith(trigger) for trigger in factual_triggers):
            return "fact"
        dynamic_triggers = ["latest", "recent", "best", "compare", "news", "update", "new", "today"]
        if any(trigger in normalized for trigger in dynamic_triggers):
            return "dynamic"
        return "fact"

    async def search(self, query: str, limit: int = 3) -> SearchResponse:
        normalized = self._normalize_query(query)
        if not normalized:
            raise ValueError("Search query must not be empty")

        cache_key = f"websearch:{normalized}:{limit}"
        cached = await self._cache.get(cache_key)
        if cached is not None:
            return SearchResponse.model_validate(cached)

        results: List[SearchResultItem] = []
        provider = "wikipedia"
        fallback_used = False
        query_type = self._classify_query(query)

        if query_type == "dynamic":
            top_results = await self._search_duckduckgo(query, limit)
            if top_results:
                provider = "duckduckgo"
            else:
                top_results = await self._search_wikipedia(query, limit)
                fallback_used = True
        else:
            top_results = await self._search_wikipedia(query, limit)
            if not top_results or len(top_results) < 2:
                ddg_results = await self._search_duckduckgo(query, limit)
                if ddg_results:
                    top_results = ddg_results
                    provider = "duckduckgo"
                    fallback_used = True

        for item in top_results[:limit]:
            url = item.get("url")
            if not url:
                continue
            page_text = await self._fetch_page_text(url)
            results.append(SearchResultItem(
                title=item.get("title") or url,
                url=url,
                snippet=item.get("snippet") or "",
                source=provider,
                text=page_text,
            ))

        response = SearchResponse(
            query=query,
            provider=provider,
            results=results,
            fallback_used=fallback_used,
            retrieved_at=datetime.utcnow(),
        )

        await self._cache.set(cache_key, response.model_dump())
        return response
