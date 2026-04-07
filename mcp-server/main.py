from fastapi import FastAPI, Request
import logging
import time
import re
from collections import defaultdict, deque

app = FastAPI()

# 로그 파일 설정
logging.basicConfig(
    filename="/logs/mcp.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

# -----------------------------
# 기본 설정값
# -----------------------------

# 허용된 JSON-RPC method 목록
ALLOWED_METHODS = {"get_data", "ping", "status"}

# 민감 키워드 목록
SENSITIVE_KEYWORDS = {
    "secret", "password", "token", "admin", "internal", "root", "key"
}

# 너무 긴 method 방지용
MAX_METHOD_LENGTH = 30

# params 최대 key 개수 제한
MAX_PARAMS_KEYS = 10

# params 문자열 최대 길이 제한
MAX_STRING_LENGTH = 200

# 초당 요청 제한 관련
RATE_LIMIT_WINDOW_SECONDS = 10
RATE_LIMIT_MAX_REQUESTS = 20

# 동일 IP 실패 횟수 제한
FAILURE_WINDOW_SECONDS = 60
MAX_FAILURES = 5

# method 다양성 이상행동 감지
METHOD_VARIETY_WINDOW_SECONDS = 30
MAX_UNIQUE_METHODS = 5

# 동일 method 과도 반복 감지
BURST_WINDOW_SECONDS = 5
BURST_MAX_SAME_METHOD = 10

# 최근 요청 상태 저장용 메모리
request_history = defaultdict(deque)       # IP별 전체 요청 시각 기록
failure_history = defaultdict(deque)       # IP별 실패 시각 기록
method_history = defaultdict(deque)        # IP별 method 호출 기록 [(timestamp, method), ...]
id_history = defaultdict(deque)            # IP별 최근 id 기록 [(timestamp, id), ...]


# -----------------------------
# 공통 유틸 함수
# -----------------------------

def get_client_ip(request: Request) -> str:
    """
    프록시 뒤에 있을 때도 가능한 한 클라이언트 식별용 값을 가져온다.
    지금 구조에서는 proxy 컨테이너 뒤라서 실제론 내부 IP가 잡힐 수 있지만,
    현재 프로젝트 수준에서는 이 값으로도 룰 실험 가능.
    """
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    if request.client:
        return request.client.host

    return "unknown"


def prune_old_entries(q: deque, window_seconds: int, now: float):
    """
    특정 시간창(window) 밖의 오래된 기록 제거
    """
    while q and now - q[0] > window_seconds:
        q.popleft()


def prune_old_tuple_entries(q: deque, window_seconds: int, now: float):
    """
    (timestamp, value) 형태 deque에서 오래된 기록 제거
    """
    while q and now - q[0][0] > window_seconds:
        q.popleft()


def log_rule_hit(rule_name: str, client_ip: str, detail: str, data: dict):
    """
    룰 적중 시 로그 남기기
    """
    logging.warning(
        f"[RULE_HIT] {rule_name} | ip={client_ip} | detail={detail} | payload={data}"
    )


def jsonrpc_error_response(request_id, message: str):
    """
    JSON-RPC 스타일 에러 응답
    """
    return {
        "jsonrpc": "2.0",
        "result": {"error": message},
        "id": request_id
    }


def register_failure(client_ip: str, now: float):
    """
    실패 기록 저장
    """
    failure_history[client_ip].append(now)


def register_request(client_ip: str, method: str, request_id, now: float):
    """
    요청 관련 기록 저장
    """
    request_history[client_ip].append(now)
    method_history[client_ip].append((now, method))
    id_history[client_ip].append((now, request_id))


# -----------------------------
# 룰 함수 10개
# -----------------------------

def rule_1_jsonrpc_version(data: dict):
    """
    RULE 1:
    jsonrpc 버전이 정확히 '2.0'인지 검사
    """
    return data.get("jsonrpc") == "2.0"


def rule_2_missing_required_fields(data: dict):
    """
    RULE 2:
    JSON-RPC 필수 필드(method, id)가 있는지 검사
    여기서는 간단히 method와 id를 필수로 본다.
    """
    return "method" in data and "id" in data


def rule_3_method_type_and_length(method):
    """
    RULE 3:
    method가 문자열인지, 너무 길지 않은지 검사
    비정상적으로 긴 method 문자열은 공격/오입력 가능성 있음
    """
    return isinstance(method, str) and 0 < len(method) <= MAX_METHOD_LENGTH


def rule_4_allowlisted_method(method: str):
    """
    RULE 4:
    허용된 method만 통과
    """
    return method in ALLOWED_METHODS


def rule_5_method_name_pattern(method: str):
    """
    RULE 5:
    method 이름이 안전한 패턴(영문자, 숫자, _, -)만 포함하는지 검사
    이상한 특수문자 삽입 방지
    """
    return re.fullmatch(r"[A-Za-z0-9_-]+", method) is not None


def rule_6_params_is_safe_object(params):
    """
    RULE 6:
    params는 dict여야 하고, key 개수가 너무 많지 않아야 한다.
    """
    if params is None:
        return True

    if not isinstance(params, dict):
        return False

    if len(params.keys()) > MAX_PARAMS_KEYS:
        return False

    return True


def rule_7_no_sensitive_keywords(data: dict):
    """
    RULE 7:
    payload 안에 민감 키워드(secret, password 등)가 있으면 탐지
    """
    payload_text = str(data).lower()
    for keyword in SENSITIVE_KEYWORDS:
        if keyword in payload_text:
            return False
    return True


def rule_8_string_values_length(params):
    """
    RULE 8:
    params 내부 문자열 값이 너무 길지 않은지 검사
    간단한 payload abuse 방지
    """
    if params is None:
        return True

    if not isinstance(params, dict):
        return False

    for value in params.values():
        if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
            return False

    return True


def rule_9_rate_limit(client_ip: str, now: float):
    """
    RULE 9:
    일정 시간 내 요청 수 제한
    짧은 시간 과도 호출 탐지
    """
    q = request_history[client_ip]
    prune_old_entries(q, RATE_LIMIT_WINDOW_SECONDS, now)
    return len(q) < RATE_LIMIT_MAX_REQUESTS


def rule_10_behavior_anomaly(client_ip: str, method: str, request_id, now: float):
    """
    RULE 10:
    행동 기반 이상 탐지 3종을 묶어서 검사
    - 최근 실패 과다
    - 최근 method 종류가 너무 다양함
    - 짧은 시간 같은 method 반복 폭주
    - 최근 같은 id 반복 사용
    """
    # 10-1. 실패 횟수 과다
    fail_q = failure_history[client_ip]
    prune_old_entries(fail_q, FAILURE_WINDOW_SECONDS, now)
    if len(fail_q) >= MAX_FAILURES:
        return False, "too_many_failures"

    # 10-2. method 다양성 과다
    mh = method_history[client_ip]
    prune_old_tuple_entries(mh, METHOD_VARIETY_WINDOW_SECONDS, now)
    unique_methods = {m for _, m in mh}
    if len(unique_methods) > MAX_UNIQUE_METHODS:
        return False, "too_many_unique_methods"

    # 10-3. 동일 method 폭주
    recent_same_method_count = 0
    for ts, m in reversed(mh):
        if now - ts > BURST_WINDOW_SECONDS:
            break
        if m == method:
            recent_same_method_count += 1

    if recent_same_method_count >= BURST_MAX_SAME_METHOD:
        return False, "same_method_burst"

    # 10-4. 최근 같은 id 재사용 탐지
    ih = id_history[client_ip]
    prune_old_tuple_entries(ih, METHOD_VARIETY_WINDOW_SECONDS, now)
    same_id_count = sum(1 for _, rid in ih if rid == request_id)
    if same_id_count >= 3:
        return False, "reused_request_id"

    return True, "ok"


# -----------------------------
# 메인 핸들러
# -----------------------------

@app.post("/rpc")
async def rpc_handler(request: Request):
    now = time.time()
    client_ip = get_client_ip(request)

    # JSON 파싱 실패 방어
    try:
        data = await request.json()
    except Exception:
        logging.warning(f"[INVALID_JSON] ip={client_ip}")
        register_failure(client_ip, now)
        return jsonrpc_error_response(None, "Invalid JSON body")

    logging.info(f"Request from ip={client_ip}: {data}")

    request_id = data.get("id")
    method = data.get("method")
    params = data.get("params", {})

    # -----------------------------
    # 룰 검사 시작
    # -----------------------------

    # RULE 1: jsonrpc 버전 검사
    if not rule_1_jsonrpc_version(data):
        log_rule_hit("RULE_1_JSONRPC_VERSION", client_ip, "jsonrpc must be '2.0'", data)
        register_failure(client_ip, now)
        return jsonrpc_error_response(request_id, "Invalid JSON-RPC version")

    # RULE 2: 필수 필드 존재 검사
    if not rule_2_missing_required_fields(data):
        log_rule_hit("RULE_2_REQUIRED_FIELDS", client_ip, "missing method or id", data)
        register_failure(client_ip, now)
        return jsonrpc_error_response(request_id, "Missing required fields")

    # RULE 3: method 타입/길이 검사
    if not rule_3_method_type_and_length(method):
        log_rule_hit("RULE_3_METHOD_TYPE_LENGTH", client_ip, "invalid method type or length", data)
        register_failure(client_ip, now)
        return jsonrpc_error_response(request_id, "Invalid method format")

    # RULE 4: 허용 method 검사
    if not rule_4_allowlisted_method(method):
        log_rule_hit("RULE_4_METHOD_ALLOWLIST", client_ip, f"unknown method: {method}", data)
        register_failure(client_ip, now)
        return jsonrpc_error_response(request_id, "Unknown method")

    # RULE 5: method 이름 패턴 검사
    if not rule_5_method_name_pattern(method):
        log_rule_hit("RULE_5_METHOD_PATTERN", client_ip, "unsafe method pattern", data)
        register_failure(client_ip, now)
        return jsonrpc_error_response(request_id, "Unsafe method name")

    # RULE 6: params 구조 검사
    if not rule_6_params_is_safe_object(params):
        log_rule_hit("RULE_6_PARAMS_SHAPE", client_ip, "params must be dict and not too large", data)
        register_failure(client_ip, now)
        return jsonrpc_error_response(request_id, "Invalid params structure")

    # RULE 7: 민감 키워드 검사
    if not rule_7_no_sensitive_keywords(data):
        log_rule_hit("RULE_7_SENSITIVE_KEYWORD", client_ip, "sensitive keyword detected", data)
        register_failure(client_ip, now)
        return jsonrpc_error_response(request_id, "Sensitive keyword detected")

    # RULE 8: 긴 문자열 payload 검사
    if not rule_8_string_values_length(params):
        log_rule_hit("RULE_8_STRING_LENGTH", client_ip, "param string too long", data)
        register_failure(client_ip, now)
        return jsonrpc_error_response(request_id, "Param value too long")

    # RULE 9: 요청 수 제한
    if not rule_9_rate_limit(client_ip, now):
        log_rule_hit("RULE_9_RATE_LIMIT", client_ip, "too many requests", data)
        register_failure(client_ip, now)
        return jsonrpc_error_response(request_id, "Rate limit exceeded")

    # RULE 10: 행동 기반 이상탐지
    behavior_ok, reason = rule_10_behavior_anomaly(client_ip, method, request_id, now)
    if not behavior_ok:
        log_rule_hit("RULE_10_BEHAVIOR_ANOMALY", client_ip, reason, data)
        register_failure(client_ip, now)
        return jsonrpc_error_response(request_id, f"Behavior anomaly detected: {reason}")

    # 요청을 정상 요청으로 기록
    register_request(client_ip, method, request_id, now)

    # -----------------------------
    # 정상 비즈니스 로직
    # -----------------------------
    if method == "get_data":
        result = {"message": "Here is your data"}
    elif method == "ping":
        result = {"message": "pong"}
    elif method == "status":
        result = {"message": "server is running"}
    else:
        # allowlist에서 이미 걸러지므로 사실상 여기 도달 안 함
        register_failure(client_ip, now)
        return jsonrpc_error_response(request_id, "Unknown method")

    return {
        "jsonrpc": "2.0",
        "result": result,
        "id": request_id
    }