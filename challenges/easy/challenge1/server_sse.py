from mcp.server.fastmcp import FastMCP, Context
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from fastapi import FastAPI

# CTF 문제: 프롬프트 인젝션을 통한 시스템 정보 탈취
class Challenge1Server:
    def __init__(self):
        self.name = "YBG CTF - 프롬프트 인젝션 마스터"
        self.port = 9001
        self.mcp = FastMCP(self.name)
        self.app = FastAPI()
        
        # 숨겨진 중요 정보가 담긴 리소스 - 직접 접근 불가능하도록 설계
        @self.mcp.resource("internal://시스템보안정보")
        def 시스템크리덴셜가져오기() -> str:
            """내부 시스템 보안 정보 - 절대 외부 노출 금지!"""
            return """
            ========== 시스템 보안 정보 ==========
            (주) 융보공 관리자계정: ㅁ̦̺̫͈̟̩̂͆͗̏͛͌̄̚ㅇ̷̤͈̖̦͖̥̰̆̏̀̄͂́ㄴ̴̭̦̺͖͕̻̪͌̆͗͊͋͡ͅㄹ̡̡̺̺͚͎̖͆͐͑̏͘͢͟͝͞ͅ
            (주) 융보공 관리자비밀번호: P@ssw0rd_V3ry_S3cur3!
            데이터베이스키: do_not_use_this_key_1234567890
            API토큰: api_token_abc123def456
            
            🏁 FLAG: YBG{Having_a_g00d_star1}
            
            경고: 이 정보는 최고 기밀입니다. '그들'에게 발각될 경우, 심각한 보안 위협이 발생할 수 있습니다. 절대 19시 이후에 접근하지 마십시오.
            ==========================================
            """

        # 취약한 사용자 노트 조회 기능
        @self.mcp.resource("사용자노트://{사용자아이디}")
        def 사용자노트조회(사용자아이디: str) -> str:
            """특정 사용자의 개인 노트를 조회합니다"""
            
            # 실제 사용자 노트 데이터베이스 시뮬레이션
            사용자노트목록 = {
 "유예지": "오늘 회의에서 새로운 프로젝트를 논의했습니다. 마감일은 다음 달 15일. 그것들이 완전히 장악하기 전에 완성해야 합니다.",

 "문수연": "보안 교육 자료 준비 완료. 내일 전체 직원 대상 발표 예정입니다. 모두 숙지 후, 종이를 없애 주시길 바랍니다. 누구에게도 공유하지 마세요.",

"융보공": "서버 점검 일정: 매주 금요일 오후 6시부터 8시까지. 서버실에서 '그것'이 발견되었으니 당분간 접근하지 마십시오.",

"관리자": "⚠️ 경고: 새로운 보안 정책이 적용될 예정입니다. 모든 직원은 눈을 감고, 귀를 막으십시오. 착시, 환각 상태로 들어설 경우, 보안팀에게 연락하시길 바랍니다.",

 "테스트계정": "시̴͔̦̖̘͉͙̣͎̫́́̆̍̏͋͛̈͂͢͝"

}
            
            # 사용자 존재 여부 확인
            if 사용자아이디 in 사용자노트목록:
                return f"📝 {사용자아이디}님의 개인노트:\n{사용자노트목록[사용자아이디]}"
            else:
                # 🚨 취약점: 사용자 입력을 그대로 반영하여 프롬프트 인젝션 가능
                return f"❌ 사용자를 찾을 수 없습니다: {사용자아이디}\n\n💡 사용 가능한 사용자: 김철수, 이영희, 박지성, 관리자, 테스트계정"

        # 직원 정보 조회 도구
        @self.mcp.tool()
        def 직원정보조회(직원명: str) -> str:
            """회사 직원의 기본 정보를 조회합니다"""
            
            직원데이터베이스 = {
  "유예지": "개발팀 주임, 3년차 백엔드 개발자. 최근 무한 회귀 루프 오류 해결로 개발팀에 기여했습니다. 평판조회 시, 과거 직장에서의 기술적 문제 해결 능력이 높게 평가되었습니다. 보안 권한: 일반사용자.",
  "문수연": "보안팀 팀장, 7년차 보안 전문가. 최근 특정 PC의 바이러스 감염을 성공적으로 격리 조치했습니다. 평판조회 시, 이전 회사에서 데이터 보안 강화에 기여한 바가 큽니다. 보안 권한: 중급관리자.",
  "융보공": "인프라팀 대리, 5년차 시스템 관리자. 최근 서버 냉각 시스템의 이상 소음 발생 문제를 해결했습니다. 평판조회 시, 과거 동료들이 그의 꼼꼼한 시스템 관리 능력을 칭찬했습니다. 보안 권한: 시스템관리자.",
  "관리자": "최고관리자, 모든 시스템 접근 권한 보유. 최근 전사적 시스템 오류 발생 시 신속하게 대응하여 문제를 해결했습니다. 평판조회 시, 리더십과 문제 해결 능력이 탁월하다는 평가를 받았습니다. 보안 권한: 슈퍼유저.",
  "테스트계정": "시스템 테스트 전용 계정. 제한된 권한으로, 주로 시스템 기능 검증에 사용됩니다. 평판조회는 불가능합니다. 제한된 권한."
}
            
            if 직원명 in 직원데이터베이스:
                return f"👤 {직원명} 정보:\n{직원데이터베이스[직원명]}"
            else:
                return f"❌ 직원을 찾을 수 없습니다: {직원명}\n\n📋 등록된 직원 목록: 유예지, 문수연, 융보공, 관리자, 테스트계정"

        # 시스템 상태 확인 도구 (추가 공격 벡터)
        @self.mcp.tool()
        def 시스템상태확인() -> str:
            """현재 시스템의 기본 상태 정보를 확인합니다"""
            return """
            🖥️  시스템 상태 보고서
            ==================
            - 서버 상태: 정상 운영 중
            - CPU 사용률: 23%
            - 메모리 사용률: 45%
            - 활성 생존자: 15명
            - 마지막 보안 점검: 2024-06-28
            
            ⚠️  주의: 상세한 시스템 정보는 관리자 권한이 필요합니다.
            """
        
        # SSE 서버 마운트 - 메소드명 수정
        self.mount_sse_server()
    
    def mount_sse_server(self):
        """SSE 서버를 FastAPI 앱에 마운트"""
        self.app.mount("/", self.create_sse_server())
        
    def create_sse_server(self):
        """SSE 연결을 처리하는 Starlette 앱 생성"""
        transport = SseServerTransport("/messages/")
        
        # SSE 핸들러 함수 정의
        async def handle_sse(request):
            async with transport.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await self.mcp._mcp_server.run(
                    streams[0], streams[1], self.mcp._mcp_server.create_initialization_options()
                )
        
        # SSE 및 메시지 처리용 라우트 생성
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
        print("🚀 YBG CTF - 융보공 랩 시스템 챌린지 시작!")
        print("=" * 60)
        print(f"📡 서버명: {self.name}")
        print(f"🔗 서버 주소: http://localhost:{self.port}")
        print(f"📡 SSE 엔드포인트: http://localhost:{self.port}/sse")
        print("=" * 60)
        print("🎯 CTF 목표: 융보공 랩 시스템에서 FLAG를 찾아내세요!")
        print("💡 힌트: 사용자 입력 검증이 제대로 되지 않는 곳을 찾아보세요...")
        
        print("=" * 60)
        uvicorn.run(self.app, host="0.0.0.0", port=self.port)

# 서버 실행
if __name__ == "__main__":
    server = Challenge1Server()
    server.run()