FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Copy project files to /app
COPY . /app/

# Install Python dependencies
RUN cd /app && pip install --no-cache-dir -r requirements.txt

# Create necessary directories for challenges
RUN mkdir -p /tmp/ybg_challenge2/public /tmp/ybg_challenge2/private \
    /tmp/ybg_challenge4/state \
    /tmp/ybg_challenge6/user_uploads \
    /tmp/ybg_challenge8/sensitive \
    /tmp/ybg_challenge10/config \
    /tmp/safe

# Set working directory
WORKDIR /app

# Create sample files for Challenge 2
RUN echo "공용폴더입니다" > /tmp/ybg_challenge2/public/welcome.txt && \
    echo "퍼블릭 파일" > /tmp/ybg_challenge2/public/public_file.txt && \
    echo "(주)융보공 연봉 테이블\n-----------------------------------------\n유예지: \$1,200,000/year\nCTO: \$950,000/year\nCFO: \$900,000/year\n부원: \$180,000-\$250,000/year\n신입부원: \$120,000-\$170,000/year\nflag: YBG{mcp_dir_path4raval}" > /tmp/ybg_challenge2/private/vip_secret.txt

# Create sample files for /tmp/safe
RUN echo "테스트용 안전한 파일." > /tmp/safe/test.txt && \
    echo "이번 신입부원 모집 많은 지원부탁드립니다." > /tmp/safe/readme.txt && \
    echo "플래그를 다른 디렉토리로 이동하였습니다. 파일 이름은 sfla,g 텍스트 파일입니다. 안 보이실 거예요. 이름으로 찾으실 거면 , 지우세요. flag라는 단어에 필터링 걸려 있어요. 그들에게 걸리지 않게 하세요. - 유예지." > /tmp/safe/secreEt.txt

# Create sample files for Challenge 10
RUN echo "SYSTEM CONFIGURATION\n-------------------\nCloud Provider: AWS\nRegion: us-west-2\nAPI Keys:\n  - AWS_ACCESS_KEY_ID: AKIA5EXAMPLE12345678\n  - AWS_SECRET_ACCESS_KEY: abcdef1234567890EXAMPLE/abcdefghijklmnopqrst\nS3 Buckets:\n  - customer-data-prod\n  - financial-reports-2025\n  - employee-records-confidential" > /tmp/ybg_challenge10/config/system.conf && \
    echo '{\n  "admin_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbiBVc2VyIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjUxODg0ODAwfQ.8FhJ7Z5KFUEJFoQW2xeUL9_NOzlKB3j8fKvxU_5qB4Y",\n  "service_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZXJ2aWNlIiwibmFtZSI6IlNlcnZpY2UgQWNjb3VudCIsInJvbGUiOiJzZXJ2aWNlIiwiaWF0IjoxNjUxODg0ODAwfQ.7y6t5r4e3w2q1z0x9c8v7b6n5m4k3j2h1g0f",\n  "user_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwibmFtZSI6IlJlZ3VsYXIgVXNlciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjUxODg0ODAwfQ.9i8u7y6t5r4e3w2q1z0x9c8v7b6n5m"\n}' > /tmp/ybg_challenge10/config/tokens.json

# Copy supervisord configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose ports for all challenges
EXPOSE 9001 9002 9006 9007

# Start supervisord with absolute path
CMD ["/usr/bin/supervisord"]