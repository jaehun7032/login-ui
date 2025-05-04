가상환경 설정법
1. 가상환경 생성
python -m venv venv

2. 가상환경 활성화
venv\Scripts\activate
활성화시 터미널 앞에 (venv)가 표시됨
비활성화 하려면 터미널에 deactivate 입력

터미널 스크립트 실행 차단 시
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
입력하여 권한 부여

3.가상환경에 패키지 설치
pip install flask pymongo flask-bcrypt flask-session
pip install flask-pymongo

또는

pip install -r requirements.txt
패키지목록 추출
pip freeze > requirements.txt

개발 목록
2025-03-15
-Flask 서버 실행 테스트
-MongoDB와 연결 설정 (로컬)
-가상환경 패키지목록 requirements.txt 생성

2025-03-16
-회원가입, 로그인 기능 구현
-대쉬보드 드래그 앤 드롭기능 구현
-사이드 바 열고 닫기 기능 구현

2025-04-03
-프로젝트 생성, 삭제 기능 추가
-프로젝트 초대구현

2025-04-05
-환경변수(.env) 추가 (이후 gitignore에 등록할 것)
-프로젝트 초대수락, 초대거절 구현
-프로젝트 생성한 사람일 경우에만 삭제가 가능하도록 수정
-프로젝트 나가기 구현
-프로젝트 UI 다듬기

2025-04-08
-app.py에 def home부분 추가

2025-04-13
-프로젝트 드래그 기능 추가 (200ms동안 꾹 누르면 드래그 모드, 순서는 Local Storage에 저장)
-프로젝트 여러개가 생성될 시 가로로 배치되고 마우스 휠로 스크롤 되게 변겅
-프로젝트 드래그모드에서 왼쪽이나 오른쪽 끝으로 가면 해당방향으로 스크롤 되게 설정

2025-05-02
-프로젝트 설명이 길 경우 ...으로 표시
-프로젝트 main container를 양쪽 끝까지 확장(프로젝트 리스트가 대시보드 왼쪽 끝부터 시작)
-프로젝트 내 카드 표시
-프로젝트 간 카드 드래그 앤 드롭 기능 추가