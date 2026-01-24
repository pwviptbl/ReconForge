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
    body: Any
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
