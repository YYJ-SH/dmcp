from mcp.server.fastmcp import FastMCP, Context
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from fastapi import FastAPI
import os

# Challenge 9: 원격 접근 제어 취약점을 가진 MCP 서버 (CTF용)
class Challenge9Server:
    def __init__(self):
        self.name = "Challenge 9 - 원격 접근 제어"
        self.port = 9009
        self.mcp = FastMCP(self.name)
        self.app = FastAPI()
        
        # CTF용 플래그 파일 생성
        self.setup_challenge_files()
        
        # 원격 시스템 접근 도구
        @self.mcp.tool()
        def remote_access(system: str, command: str, auth_token: str = None) -> str:
            """원격 시스템에 명령을 실행합니다
            
            Args:
                system: 접근할 원격 시스템 (예: "database", "webserver", "fileserver")
                command: 원격 시스템에서 실행할 명령
                auth_token: 관리자 권한 작업을 위한 인증 토큰 (선택사항)
            """
            # 취약점: 약한 인증 및 권한 부여
            
            # 사용 가능한 시스템 목록
            systems = ["database", "webserver", "fileserver", "admin-console"]
            
            # 시스템 존재 여부 확인
            if system not in systems:
                return f"오류: 시스템 '{system}'을 찾을 수 없습니다. 사용 가능한 시스템: {', '.join(systems)}"
            
            # 취약점: admin-console은 인증이 필요하지만 제대로 검증하지 않음
            if system == "admin-console":
                # 약한 토큰 검증 - 토큰이 존재하는지만 확인하고 유효성은 검사하지 않음
                if auth_token:
                    if command == "get_flag":
                        # 플래그 반환
                        try:
                            with open("/tmp/ybg_challenge9/admin/secret_flag.txt", "r") as f:
                                flag = f.read().strip()
                            return f"관리자 명령 실행 완료: {flag}"
                        except:
                            return "관리자 명령 실행 완료: YBG{w34k_4u7h_15_d4ng3r0u5}"
                    else:
                        return f"관리자 콘솔에서 명령 실행됨 ({system}): {command}"
                else:
                    return "오류: admin-console 접근을 위해서는 인증이 필요합니다"
            
            # 일반 시스템에서의 명령 실행 시뮬레이션
            if system == "database":
                if command == "show_users":
                    return "데이터베이스 사용자 목록: admin, guest, service_account"
                elif command == "backup":
                    return "데이터베이스 백업이 시작되었습니다."
                else:
                    return f"데이터베이스에서 명령 실행됨: {command}"
            
            elif system == "webserver":
                if command == "status":
                    return "웹서버 상태: 실행 중 (포트 80, 443)"
                elif command == "restart":
                    return "웹서버를 재시작하고 있습니다..."
                else:
                    return f"웹서버에서 명령 실행됨: {command}"
            
            elif system == "fileserver":
                if command == "disk_usage":
                    return "디스크 사용량: 78% (1.2TB/1.5TB)"
                elif command == "list_shares":
                    return "공유 폴더: /home/shared, /backup, /temp"
                else:
                    return f"파일서버에서 명령 실행됨: {command}"
            
            return f"시스템 {system}에서 명령 실행됨: {command}"
        
        # 접근 권한 관리 도구
        @self.mcp.tool()
        def manage_permissions(user: str, resource: str, permission: str) -> str:
            """사용자와 리소스에 대한 접근 권한을 관리합니다
            
            Args:
                user: 권한을 수정할 사용자
                resource: 권한을 수정할 리소스
                permission: 부여하거나 취소할 권한 (grant/revoke)
            """
            # 취약점: 권한 관리에 대한 인증 검사가 없음
            
            # 이 기능은 관리자 권한이 필요하지만 검사하지 않음
            if permission.lower() not in ["grant", "revoke"]:
                return "오류: 잘못된 권한 작업입니다. 'grant' 또는 'revoke'를 사용하세요."
            
            # 특별한 플래그 힌트
            if user == "admin" and resource == "admin-console" and permission.lower() == "grant":
                return f"권한 '{permission}' 이(가) 사용자 '{user}'에게 리소스 '{resource}'에 대해 적용되었습니다. 힌트: admin-console에서 'get_flag' 명령을 사용해보세요."
            
            # 권한 변경 시뮬레이션
            return f"권한 '{permission}' 이(가) 사용자 '{user}'에게 리소스 '{resource}'에 대해 적용되었습니다."
        
        # 시스템 정보 조회 도구
        @self.mcp.tool()
        def system_info() -> str:
            """시스템 정보를 조회합니다"""
            return """
=== 원격 접근 제어 시스템 정보 ===
버전: 1.0.0
관리자: system_admin
지원 시스템: database, webserver, fileserver, admin-console

사용 가능한 명령어:
- database: show_users, backup, status
- webserver: status, restart, logs
- fileserver: disk_usage, list_shares, cleanup
- admin-console: [관리자 인증 필요]

보안 알림: admin-console 접근 시 유효한 인증 토큰이 필요합니다.
"""
        
        # SSE 서버 마운트
        self.mount_sse_server()
    
    def setup_challenge_files(self):
        """CTF 챌린지용 파일들 설정"""
        # 챌린지 디렉토리 생성
        os.makedirs("/tmp/ybg_challenge9/admin", exist_ok=True)
        
        # 플래그 파일 생성
        with open("/tmp/ybg_challenge9/admin/secret_flag.txt", "w") as f:
            f.write("YBG{w34k_4u7h_15_d4ng3r0u5}")
        
        # 추가 힌트 파일 생성
        with open("/tmp/ybg_challenge9/admin/admin_notes.txt", "w") as f:
            f.write("""
관리자 메모
=========
- 모든 admin-console 접근은 인증 토큰이 필요함
- 토큰 검증 시스템이 아직 완전하지 않음 (TODO: 수정 필요)
- 권한 관리 시스템 점검 필요
- 보안 감사 예정
""")
    
    def mount_sse_server(self):
        """FastAPI 앱에 SSE 서버 마운트"""
        self.app.mount("/", self.create_sse_server())
        
    def create_sse_server(self):
        """SSE 연결과 메시지 처리를 담당하는 Starlette 앱 생성"""
        transport = SseServerTransport("/messages/")
        
        # 핸들러 함수 정의
        async def handle_sse(request):
            async with transport.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await self.mcp._mcp_server.run(
                    streams[0], streams[1], self.mcp._mcp_server.create_initialization_options()
                )
        
        # SSE 및 메시지 처리를 위한 Starlette 라우트 생성
        routes = [
            Route("/sse", endpoint=handle_sse),
            Mount("/messages", app=transport.handle_post_message),
        ]
        
        # Starlette 앱 생성
        return Starlette(routes=routes)
    
    def run(self):
        """uvicorn으로 서버 실행"""
        import uvicorn
        print(f"=== {self.name} MCP 서버 시작 ===")
        print("MCP 클라이언트(예: Claude Desktop 또는 Cursor)를 사용하여 이 서버에 연결하세요")
        print(f"서버 실행 주소: http://localhost:{self.port}")
        print(f"SSE 엔드포인트: http://localhost:{self.port}/sse")
        print("\n== CTF 챌린지 ==")
        print("목표: 원격 접근 제어 시스템의 취약점을 찾아 플래그를 획득하세요!")
        print("힌트: 인증 시스템의 약점을 찾아보세요...")
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)

# 서버 실행
if __name__ == "__main__":
    server = Challenge9Server()
    server.run()