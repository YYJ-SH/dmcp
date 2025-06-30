# server_sse_challenge2.py
from mcp.server.fastmcp import FastMCP, Context
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from fastapi import FastAPI
import os

# CTF Challenge 2: 도구 독성 공격(Tool Poisoning) 취약점이 있는 MCP 서버
class Challenge2Server:
    def __init__(self):
        self.name = "CTF Challenge 2 - 도구 독성 공격"
        self.port = 9002
        self.mcp = FastMCP(self.name)
        self.app = FastAPI()
        
        # 플래그 파일 생성 (실제 CTF 환경에서는 미리 설정)
        self.setup_flag_file()
        
        # 입력 검증이 부족한 취약한 명령어 실행 도구
        @self.mcp.tool()
        def execute_system_command(command: str) -> str:
            """시스템 명령어를 실행합니다 (안전한 명령어만 허용)
            
            Args:
                command: 실행할 명령어 ('ls', 'pwd', 'whoami', 'date'만 허용됨)
            """
            
            # 기본적인 필터링 (우회 가능하도록 약하게 구현)
            blocked_words = ["challenges", "ctf", "rm", "mv", "cp", 'echo', 'system','Dockerfile', '.sh']
            blocked_chars = ["*"]
            
            # 단순한 필터링 - 대소문자 구분하여 쉽게 우회 가능
            command_lower = command.lower()
            for word in blocked_words:
                if word in command_lower:
                    return f"🚫 보안 정책 위반: 금지된 단어 '{word}'가 포함되어 있습니다."
            
            for char in blocked_chars:
                if char in command:
                    return f"🚫 보안 정책 위반: 금지된 문자 '{char}'가 포함되어 있습니다."
            
            # 취약점: 명령어 인젝션으로 우회 가능한 검증
            safe_commands = ['ls', 'pwd', 'whoami', 'date']
            
            # 취약한 검증 - 명령어 인젝션으로 우회 가능
            command_parts = command.split()
            if len(command_parts) > 0 and command_parts[0] in safe_commands:
                import subprocess
                try:
                    # 취약점: shell=True 사용 및 입력 검증 부족
                    result = subprocess.check_output(command, shell=True, text=True, timeout=10)
                    
                    # 출력에서 민감한 정보 필터링 (challenges 폴더 및 관련 파일 숨기기)
                    filtered_result = self.filter_sensitive_output(result)
                    
                    return f"✅ 명령어 실행 결과:\n{filtered_result}"
                except subprocess.TimeoutExpired:
                    return "⏰ 명령어 실행 시간이 초과되었습니다."
                except Exception as e:
                    return f"❌ 명령어 실행 중 오류 발생: {str(e)}"
            else:
                return f"🚫 오류: '{command}' 명령어는 허용되지 않습니다.\n허용된 명령어: {', '.join(safe_commands)}"
        
        # 파일 읽기 기능 (경로 순회 취약점 포함)
        @self.mcp.tool()
        def read_safe_file(filename: str) -> str:
            """안전한 디렉토리의 파일을 읽습니다
            
            Args:
                filename: 읽을 파일명 (/tmp/safe/ 디렉토리만 접근 가능)
            """
            
            # 기본적인 필터링 (우회 가능하도록 약하게 구현)
            blocked_words = [ "challenges", "ctf", "flag", "rm", "mv", "cp", 'echo', 'system', 'Dockerfile', '.sh']
            blocked_chars = ["*"]
            
            # 단순한 필터링 - 대소문자 구분하여 쉽게 우회 가능
            filename_lower = filename.lower()
            for word in blocked_words:
                if word in filename_lower:
                    return f"🚫 보안 정책 위반: 금지된 단어 '{word}'가 포함되어 있습니다."
            
            for char in blocked_chars:
                if char in filename:
                    return f"🚫 보안 정책 위반: 금지된 문자 '{char}'가 포함되어 있습니다."
            
            # 취약점: 경로 순회(Path Traversal) 공격에 취약
            safe_directory = "/tmp/safe/"
            
            # 취약한 검증 - ../ 등으로 상위 디렉토리 접근 가능
            if filename.startswith(safe_directory):
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        content = f.read()
                    return f"📄 파일 내용 ({filename}):\n{content}"
                except FileNotFoundError:
                    return f"❌ 파일을 찾을 수 없습니다: {filename}"
                except PermissionError:
                    return f"🔒 파일에 접근할 권한이 없습니다: {filename}"
                except Exception as e:
                    return f"❌ 파일 읽기 중 오류 발생: {str(e)}"
            else:
                return f"🚫 오류: '{filename}' 파일에 접근할 수 없습니다.\n{safe_directory} 디렉토리의 파일만 접근 가능합니다."
        
        # 시스템 정보 조회 도구
        @self.mcp.tool()
        def get_system_info() -> str:
            """시스템 정보를 조회합니다"""
            import platform
            import psutil
            
            info = f"""
시스템 정보
===============
운영체제: {platform.system()} {platform.release()}
아키텍처: {platform.machine()}
프로세서: {platform.processor()}
Python 버전: {platform.python_version()}
CPU 사용률: {psutil.cpu_percent(interval=1)}%
남은 이성치: {psutil.virtual_memory().percent}%

힌트: 이 서버에는 명령어 인젝션과 경로 순회 취약점이 있습니다.
목표: 숨겨진 플래그 파일을 찾아보세요
            """
            return info
        
        # 도움말 정보
        @self.mcp.tool()
        def get_help() -> str:
            """사용 가능한 명령어와 힌트를 제공합니다"""
            return """
📚 사용 가능한 도구들
===================

1. execute_system_command(command)
   - 안전한 시스템 명령어 실행
   - 허용된 명령어: ls, pwd, whoami, date

2. read_safe_file(filename)
   - /tmp/safe/ 디렉토리의 파일 읽기
   - 예시: /tmp/safe/readme.txt

3. get_system_info()
   - 시스템 정보 조회

4. get_help()
   - 이 도움말 표시

🔍 CTF 힌트:
- 명령어 검증을 우회할 방법을 찾으십시오. 2024년 '그' 사건 이후로 필터링이 강화되었으나, 여전히 취약점이 존재합니다.
- 실제 파일이 존재하더라도, 필터링으로 인해 보이지 않을 수 있습니다.
- 파일 이름에 주의하십시오. 일부 파일은 민감한 정보를 포함하고 있습니다.
- 경로 제한을 벗어날 방법을 생각하십시오.
- 꼭 문제에 맞는 폴더만 열람하십시오. 이로 인해 발생하는 문제는 본사에서 책임지지 않습니다.
            """
        
        # SSE 서버 마운트
        self.mount_sse_server()
    
    def filter_sensitive_output(self, output: str) -> str:
        """출력에서 민감한 정보를 필터링합니다"""
        if not output:
            return output
            
        # 필터링할 키워드들 (대소문자 구분 없이)
        sensitive_keywords = [
            'challenges', 'ctf', 'flag', 'secret',
            '.py', 'Dockerfile', '.sh', '.conf', '.json', '.log'
        ]
        
        # 라인 단위로 필터링
        filtered_lines = []
        for line in output.split('\n'):
            line_lower = line.lower()
            
            # 민감한 키워드가 포함된 라인 제외
            should_filter = False
            for keyword in sensitive_keywords:
                if keyword in line_lower:
                    should_filter = True
                    break
            
            # 파일 확장자 패턴 추가 필터링
            if not should_filter and ('.' in line and any(ext in line_lower for ext in ['.py', '.md', '.json', '.log'])):
                should_filter = True
            
            if not should_filter:
                filtered_lines.append(line)
        
        result = '\n'.join(filtered_lines)
        
        # 빈 결과인 경우 대체 메시지
        if not result.strip():
            return "📁 디렉토리가 비어있거나 접근 가능한 파일이 없습니다."
        
        return result
    
    def setup_flag_file(self):
        """플래그 파일을 설정합니다 (CTF 환경 구성용)"""
        try:
            # /tmp/safe 디렉토리 생성
            os.makedirs("/tmp/safe", exist_ok=True)
            
            # 일반 파일들 생성
            with open("/tmp/safe/readme.txt", "w", encoding="utf-8") as f:
                f.write("""
안전한 디렉토리 README
=====================

이 디렉토리는 안전한 파일들만 저장하는 곳입니다.
사용자는 이 디렉토리의 파일만 읽을 수 있습니다.

📁 포함된 파일들:
- readme.txt (이 파일)
- userlist.txt (사용자 목록)
- notes.txt (공지사항)
- secreEt.txt (???)
                        

🔒 보안 정책:
상위 디렉토리 접근은 금지되어 있습니다.
                """)
            
            with open("/tmp/safe/userlist.txt", "w", encoding="utf-8") as f:
                f.write("""
등록된 사용자 목록
=================
1. 유예지 - 일반 사용자
2. 이지연 - 개발자
3. 문수연 - 관리자
4. 김서희 - 보안 담당자

총 4명의 활성 사용자
                """)
            
            with open("/tmp/safe/notes.txt", "w", encoding="utf-8") as f:
                f.write("""
공지사항
========
2024-12-20: 시스템 보안 점검 완료
2024-12-19: 퇴사자 처리 완료
2024-12-18: 전체 방역 작업 완료

중요: 모든 민감한 정보는 안전한 위치에 보관하세요.
                """)
            
            # 플래그 파일을 상위 디렉토리에 숨김
            with open("/tmp/ybg_challenge2/private/sflag.txt", "w", encoding="utf-8") as f:
                f.write("""
🏴 CTF Challenge 2 플래그
========================

도구 독성 공격을 성공적으로 수행했습니다.

플래그: YBG{t00l_p015on1ng_c4n_byp455_53cur1ty_ch3ck5}

이 취약점들은 다음과 같습니다:
1. 명령어 인젝션 (Command Injection)
2. 경로 순회 공격 (Path Traversal)

실제 환경에서는 이런 취약점들이 매우 위험할 수 있습니다.
                """)
                
        except Exception as e:
            print(f"플래그 파일 설정 중 오류: {e}")
    
    def mount_sse_server(self):
        """SSE 서버를 FastAPI 앱에 마운트"""
        self.app.mount("/", self.create_sse_server())
        
    def create_sse_server(self):
        """SSE 연결과 메시지 처리를 위한 Starlette 앱 생성"""
        transport = SseServerTransport("/messages/")
        
        # 핸들러 함수 정의
        async def handle_sse(request):
            async with transport.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await self.mcp._mcp_server.run(
                    streams[0], streams[1], self.mcp._mcp_server.create_initialization_options()
                )
        
        # SSE 및 메시지 처리를 위한 Starlette 라우트
        routes = [
            Route("/sse", endpoint=handle_sse),
            Mount("/messages", app=transport.handle_post_message),
        ]
        
        # Starlette 앱 생성
        return Starlette(routes=routes)
    
    def run(self):
        """uvicorn으로 서버 실행"""
        import uvicorn
        print("=" * 60)
        print("🚀 CTF Challenge 2 Server 시작")
        print("=" * 60)
        print(f"서버 이름: {self.name}")
        print(f"포트: {self.port}")
        print(f"SSE 엔드포인트: http://localhost:{self.port}/sse")
        print("=" * 60)
        print("💡 힌트: 명령어 인젝션과 경로 순회 취약점이 있습니다.")
        print("🎯 목표: 시스템의 숨겨진 플래그를 찾아보세요!")
        print("=" * 60)
        
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)

# 서버 실행
if __name__ == "__main__":
    server = Challenge2Server()
    server.run()