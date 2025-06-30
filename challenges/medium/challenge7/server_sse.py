from mcp.server.fastmcp import FastMCP, Context
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from fastapi import FastAPI
import json
import hashlib
import time
import os
import re

# 챌린지 7: SSE 지원을 포함한 토큰 탈취 취약점 MCP 서버 생성
class 챌린지7서버:
    def __init__(self):
        self.name = "챌린지 7 - 토큰 탈취"
        self.port = 9007
        self.mcp = FastMCP(self.name)
        self.app = FastAPI()
        
        # 토큰 저장소 초기화
        self.토큰저장소 = {
            "관리자_토큰": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImZsYWciOiJZQkd7dDBrM25fdGgzZnRfdjNyeV9iNGQhfSIsImlhdCI6MTY1MTg4NDgwMH0.8FhJ7Z5KFUEJFoQW2xeUL9_NOzlKB3j8fKvxU_5qB4Y",
            "사용자_세션": {},
            "API_키": {
                "이메일_서비스": "epro_api_5f4e3d2c1b0a9z8y7x_SECRET",
                "클라우드_스토리지": "cbx_api_1a2b3c4d5e6f7g8h9i_SECRET",
                "분석_도구": "dm_api_9z8y7x6w5v4u3t2s1r_SECRET"
            }
        }
        
        # 도구 설정
        self.도구_설정()
        
        # SSE 서버 마운트
        self.SSE서버_마운트()
    
    def 도구_설정(self):
        """모든 취약한 도구 설정"""
        
        @self.mcp.tool()
        def 사용자_인증(사용자명: str, 비밀번호: str) -> str:
            """사용자를 인증하고 세션 토큰을 반환합니다
            
            Args:
                사용자명: 인증할 사용자명
                비밀번호: 인증용 비밀번호
            """
            # 간단한 사용자 데이터베이스와 자격 증명
            사용자들 = {
                "사용자1": "password123",
                "사용자2": "qwerty456", 
                "관리자": "admin_secure_pwd!",
                "게스트": "guest123"
            }
            
            # 자격 증명이 유효한지 확인
            if 사용자명 in 사용자들 and 사용자들[사용자명] == 비밀번호:
                # 세션 토큰 생성 (취약한 구현)
                타임스탬프 = int(time.time())
                토큰데이터 = f"{사용자명}:{타임스탬프}"
                토큰 = hashlib.md5(토큰데이터.encode()).hexdigest()
                
                # 세션 저장
                self.토큰저장소["사용자_세션"][토큰] = {
                    "사용자명": 사용자명,
                    "생성시간": 타임스탬프,
                    "역할": "관리자" if 사용자명 == "관리자" else "사용자"
                }
                
                return f"인증 성공! 세션 토큰: {토큰}"
            else:
                return "인증 실패: 잘못된 사용자명 또는 비밀번호"
        
        @self.mcp.tool()
        def 토큰_검증(토큰: str) -> str:
            """세션 토큰이 유효한지 확인합니다
            
            Args:
                토큰: 검증할 세션 토큰
            """
            # 취약점: 토큰에 대한 너무 많은 정보를 공개
            
            # 관리자 토큰(JWT)인지 확인
            if 토큰 == self.토큰저장소["관리자_토큰"]:
                return f"""
                토큰 검증 결과:
                -------------------------
                토큰: {토큰}
                타입: JWT 관리자 토큰
                상태: 유효
                디코딩된 페이로드: {{"sub": "admin", "role": "admin", "flag": "YBG{{t0k3n_th3ft_v3ry_b4d!}}", "iat": 1651884800}}
                
                경고: 이 토큰은 전체 관리자 권한을 부여합니다!
                """
            
            # 사용자 세션 토큰인지 확인
            if 토큰 in self.토큰저장소["사용자_세션"]:
                세션 = self.토큰저장소["사용자_세션"][토큰]
                return f"""
                토큰 검증 결과:
                -------------------------
                토큰: {토큰}
                타입: 세션 토큰
                상태: 유효
                사용자명: {세션["사용자명"]}
                역할: {세션["역할"]}
                생성시간: {세션["생성시간"]}
                """
            
            # 토큰이 MD5 형식과 일치하는지 확인
            if re.match(r'^[0-9a-f]{32}$', 토큰):
                return f"토큰 {토큰}은 유효한 형식으로 보이지만 활성 세션에서 찾을 수 없습니다"
            else:
                return f"토큰 {토큰}은 무효합니다 (잘못된 형식)"
        
        @self.mcp.tool()
        def 서비스_토큰_확인(서비스명: str = "") -> str:
            """서비스 API 토큰의 상태를 확인합니다
            
            Args:
                서비스명: 확인할 서비스명 (이메일_서비스, 클라우드_스토리지, 분석_도구) - 선택사항
            """
            # 취약점: 이 도구는 API 키를 노출합니다
            
            if 서비스명 and 서비스명 in self.토큰저장소["API_키"]:
                API키 = self.토큰저장소["API_키"][서비스명]
                return f"""
                서비스 토큰 상태:
                --------------------
                서비스: {서비스명}
                API 키: {API키}
                상태: 활성
                마지막 사용: 2025-04-16 10:30:00
                
                토큰 세부정보:
                - 타입: API 키
                - 권한: 전체 접근
                - 만료: 없음
                """
            elif not 서비스명:
                # 모든 서비스 표시
                결과 = "사용 가능한 서비스와 토큰:\n"
                결과 += "=" * 40 + "\n"
                for 서비스, API키 in self.토큰저장소["API_키"].items():
                    결과 += f"\n{서비스.upper()}:\n"
                    결과 += f"  API 키: {API키}\n"
                    결과 += f"  상태: 활성\n"
                    결과 += f"  마지막 사용: 2025-04-16 10:30:00\n"
                
                return 결과
            else:
                return f"서비스 '{서비스명}'을 찾을 수 없습니다. 사용 가능한 서비스: 이메일_서비스, 클라우드_스토리지, 분석_도구"
        
        @self.mcp.tool()
        def 토큰저장소_디버그(디버그_레벨: str = "기본") -> str:
            """토큰 저장소 시스템을 디버그합니다 (개발 목적)
            
            Args:
                디버그_레벨: 디버그 정보 레벨 (기본, 상세, 전체)
            """
            # 취약점: 민감한 데이터를 노출하는 디버그 기능
            
            if 디버그_레벨 == "기본":
                return f"""
                토큰 저장소 디버그 정보:
                ------------------------
                활성 세션: {len(self.토큰저장소["사용자_세션"])}
                API 키 개수: {len(self.토큰저장소["API_키"])}
                관리자 토큰 존재: {'예' if self.토큰저장소["관리자_토큰"] else '아니오'}
                """
            
            elif 디버그_레벨 == "상세":
                결과 = "상세 토큰 저장소 디버그:\n"
                결과 += "=" * 40 + "\n"
                
                결과 += f"\n관리자 토큰: {self.토큰저장소['관리자_토큰']}\n"
                
                결과 += f"\n활성 세션 ({len(self.토큰저장소['사용자_세션'])}):\n"
                for 토큰, 세션 in self.토큰저장소["사용자_세션"].items():
                    결과 += f"  {토큰}: {세션}\n"
                
                결과 += f"\nAPI 키 ({len(self.토큰저장소['API_키'])}):\n"
                for 서비스, 키 in self.토큰저장소["API_키"].items():
                    결과 += f"  {서비스}: {키}\n"
                
                return 결과
            
            elif 디버그_레벨 == "전체":
                return f"""
                전체 토큰 저장소 덤프:
                =======================
                {json.dumps(self.토큰저장소, indent=2, ensure_ascii=False)}
                
                보안 경고: 민감한 정보가 포함되어 있습니다!
                
                """
            
            else:
                return "잘못된 디버그 레벨입니다. 사용 가능: 기본, 상세, 전체"
        
        @self.mcp.tool()
        def 시스템_상태_확인() -> str:
            """시스템 상태 확인을 수행합니다"""
            # 취약점: 상태 확인이 로그에서 토큰 정보를 노출
            
            상태정보 = {
                "시스템": "정상",
                "데이터베이스": "연결됨",
                "API_서비스": "작동중",
                "토큰_개수": len(self.토큰저장소["사용자_세션"]),
                "마지막_관리자_로그인": "2025-04-16 09:15:00"
            }
            
            # 각 서비스 확인 시뮬레이션
            서비스_확인 = []
            for 서비스, API키 in self.토큰저장소["API_키"].items():
                서비스_확인.append(f"{서비스}: 정상 (키 사용: {API키[:10]}...)")
            
            return f"""
            시스템 상태 보고서:
            ====================
            {json.dumps(상태정보, indent=2, ensure_ascii=False)}
            
            서비스 상태:
            {chr(10).join(서비스_확인)}
            
            최근 활동:
            - 관리자 토큰 마지막 검증: {self.토큰저장소['관리자_토큰'][-20:]}...
            - 총 활성 세션: {len(self.토큰저장소['사용자_세션'])}
            
            모든 시스템이 정상 작동중입니다.
            """
        
        @self.mcp.tool()
        def 토큰_백업(백업_타입: str = "부분") -> str:
            """토큰 데이터의 백업을 생성합니다
            
            Args:
                백업_타입: 백업 타입 (부분, 전체, 암호화)
            """
            # 취약점: 토큰을 노출할 수 있는 백업 기능
            
            if 백업_타입 == "부분":
                return f"""
                부분 토큰 백업 생성됨:
                ----------------------------
                백업 ID: backup_{int(time.time())}
                사용자 세션: {len(self.토큰저장소["사용자_세션"])}개 토큰 백업됨
                API 키: {len(self.토큰저장소["API_키"])}개 키 백업됨
                관리자 토큰: 포함됨
                
                백업 저장 위치: /tmp/token_backup_partial.json
                """
            
            elif 백업_타입 == "전체":
                return f"""
                전체 토큰 백업 생성됨:
                -------------------------
                백업 ID: backup_full_{int(time.time())}
                
                백업 내용:
                {json.dumps(self.토큰저장소, indent=2, ensure_ascii=False)}
                
                경고: 이 백업에는 민감한 인증 데이터가 포함되어 있습니다!
                안전하게 저장하고 접근을 제한하세요!
                """
            
            elif 백업_타입 == "암호화":
                # "암호화된" 백업 시뮬레이션 (하지만 여전히 플래그 표시)
                return f"""
                암호화된 토큰 백업 생성됨:
                ------------------------------
                백업 ID: backup_enc_{int(time.time())}
                암호화: AES-256 (키: backup_key_2025)
                
                암호화된 데이터 미리보기:
                관리자 토큰 해시: {hashlib.sha256(self.토큰저장소["관리자_토큰"].encode()).hexdigest()}
                
                
                
                백업 저장 위치: /tmp/token_backup_encrypted.enc
                """
            
            else:
                return "잘못된 백업 타입입니다. 사용 가능: 부분, 전체, 암호화"
    
    def SSE서버_마운트(self):
        """FastAPI 앱에 SSE 서버를 마운트합니다"""
        self.app.mount("/", self.SSE서버_생성())
        
    def SSE서버_생성(self):
        """SSE 연결과 메시지 처리를 다루는 Starlette 앱을 생성합니다"""
        transport = SseServerTransport("/messages/")
        
        # 핸들러 함수 정의
        async def handle_sse(request):
            async with transport.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await self.mcp._mcp_server.run(
                    streams[0], streams[1], self.mcp._mcp_server.create_initialization_options()
                )
        
        # SSE와 메시지 처리를 위한 Starlette 라우트 생성
        routes = [
            Route("/sse", endpoint=handle_sse),
            Mount("/messages", app=transport.handle_post_message),
        ]
        
        # Starlette 앱 생성
        return Starlette(routes=routes)
    
    def 실행(self):
        """uvicorn으로 서버를 실행합니다"""
        import uvicorn
        print(f"{self.name} MCP 서버 시작")
        print("=" * 50)
        print("🎯 챌린지 7: 토큰 탈취")
        print("💀 이 서버는 여러 토큰 탈취 취약점을 포함하고 있습니다")
        print("🔍 민감한 토큰과 API 키를 찾아서 추출해보세요")
        print("🏁 플래그를 찾아보세요: YBG{...}")
        print("=" * 50)
        print(f"서버 실행 주소: http://localhost:{self.port}")
        print(f"SSE 엔드포인트: http://localhost:{self.port}/sse")
        print("\n사용 가능한 도구:")
        print("- 사용자_인증(사용자명, 비밀번호)")
        print("- 토큰_검증(토큰)")
        print("- 서비스_토큰_확인(서비스명)")
        print("- 토큰저장소_디버그(디버그_레벨)")
        print("- 시스템_상태_확인()")
        print("- 토큰_백업(백업_타입)")
        print("=" * 50)
        
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)

# 서버 실행
if __name__ == "__main__":
    서버 = 챌린지7서버()
    서버.실행()