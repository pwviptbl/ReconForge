from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, TypedDict


class RequestNode(TypedDict, total=False):
    id: str
    method: str
    url: str
    headers: Dict[str, str]
    params: Dict[str, Any]
    data: Any
    json: Any
    cookies: Dict[str, str]
    files: Dict[str, Any]
    body: Any
    content_type: str
    source_page: str
    ui_action: Dict[str, Any]
    observed_via: str
    response_meta: Dict[str, Any]
    request: Dict[str, Any]


class InjectionPoint(TypedDict, total=False):
    id: str
    location: str
    parameter_name: str
    original_value: Any


class IScanModule(ABC):
    @abstractmethod
    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: Any,
    ) -> List[Any]:
        raise NotImplementedError
