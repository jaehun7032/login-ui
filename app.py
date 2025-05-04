from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_pymongo import PyMongo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from bson import ObjectId
from bson.errors import InvalidId
from pymongo.errors import PyMongoError
from datetime import datetime
from dotenv import load_dotenv
import logging
import os
import random
import string

# 환경변수 로드
load_dotenv()

# 앱 설정
app = Flask(__name__)
app.config["MONGO_URI"] = f"mongodb://{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
app.secret_key = os.getenv('SECRET_KEY')

# 이메일 관련 설정
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

mail = Mail(app)
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 유저 클래스
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data["_id"])
        self.username = user_data["username"]
        self.invitations = user_data.get("invitations", [])

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    return User(user_data) if user_data else None

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    else:
        return redirect(url_for("login"))

# 인증 코드 생성 함수
def generate_verification_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

# 이메일 보내기 함수
def send_verification_email(recipient, verification_code):
    message = Message("Email Verification", recipients=[recipient])
    message.body = f"Your verification code is: {verification_code}"
    try:
        mail.send(message)
    except Exception as e:
        print(f"Error sending email: {e}")

# 비밀번호 재설정 이메일 보내기 함수
def send_password_reset_email(recipient, reset_code):
    reset_link = url_for('password_reset_confirm', reset_code=reset_code, _external=True)
    message = Message("Password Reset Request", recipients=[recipient])
    message.body = f"To reset your password, click the link: {reset_link}"
    try:
        mail.send(message)
    except Exception as e:
        print(f"Error sending email: {e}")

# 회원가입
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        verification_code = generate_verification_code()

        # 먼저 DB에 저장
        mongo.db.users.insert_one({
            "username": username,
            "password": hashed_password,
            "email": email,
            "verification_code": verification_code,
            "verified": False,
            "invitations": []
        })

        # 그 다음 이메일 전송
        send_verification_email(email, verification_code)

        return redirect(url_for("verify_email", email=email))
    return render_template("register.html")

# 이메일 인증
@app.route("/verify_email", methods=["GET", "POST"])
def verify_email():
    email = request.args.get('email') or request.form.get('email')

    if request.method == "POST":
        verification_code = request.form["verification_code"]
        user_data = mongo.db.users.find_one({"email": email})

        if user_data:
            stored_code = user_data.get("verification_code")

            if stored_code == verification_code:
                result = mongo.db.users.update_one(
                    {"email": email},
                    {"$set": {"verified": True}}
                )

                if result.matched_count > 0:
                    user_data = mongo.db.users.find_one({"email": email})
                    user = User(user_data)
                    login_user(user)
                    session["user_id"] = user.id
                    return redirect(url_for("dashboard"))
                else:
                    return redirect(url_for("login"))
            else:
                return "인증 코드가 올바르지 않습니다. 다시 시도하세요."
        else:
            return "사용자를 찾을 수 없습니다."

    return render_template("verify_email.html", email=email)

# 로그인
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user_data = mongo.db.users.find_one({"username": username})

        if user_data and bcrypt.check_password_hash(user_data["password"], password):
            if not user_data.get("verified", False):
                return "이메일 인증이 필요합니다. 이메일을 확인해주세요."

            user = User(user_data)
            login_user(user)
            session["user_id"] = user.id
            return redirect(url_for("dashboard"))
        else:
            return "로그인 실패! 아이디 또는 비밀번호를 확인하세요."

    return render_template("login.html")

# 로그아웃
@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("user_id", None)
    return redirect(url_for("login"))

# 비밀번호 재설정 요청
@app.route("/password_reset", methods=["GET", "POST"])
def password_reset():
    if request.method == "POST":
        email = request.form["email"]
        user_data = mongo.db.users.find_one({"email": email})

        if user_data:
            reset_code = generate_verification_code()
            mongo.db.users.update_one({"email": email}, {"$set": {"reset_code": reset_code}})
            send_password_reset_email(email, reset_code)
            return redirect(url_for("password_reset_done"))
        else:
            return "No user found with that email address."
    return render_template("password_reset_request.html")

@app.route("/password_reset_done")
def password_reset_done():
    return render_template("password_reset_done.html")

@app.route("/password_reset/<reset_code>", methods=["GET", "POST"])
def password_reset_confirm(reset_code):
    if request.method == "POST":
        password = request.form["password"]
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        mongo.db.users.update_one({"reset_code": reset_code}, {"$set": {"password": hashed_password}})
        return redirect(url_for("login"))
    return render_template("password_reset_confirm.html", reset_code=reset_code)

# 아이디 찾기 요청
@app.route("/find_username", methods=["GET", "POST"])
def find_username():
    if request.method == "POST":
        email = request.form["email"]
        user_data = mongo.db.users.find_one({"email": email})

        if user_data:
            username = user_data["username"]
            message = Message("Your Username", recipients=[email])
            message.body = f"Your username is: {username}"
            try:
                mail.send(message)
                return redirect(url_for("find_username_done"))
            except Exception as e:
                print(f"Error sending email: {e}")
                return "이메일 전송 중 오류가 발생했습니다. 다시 시도해주세요."
        else:
            return "해당 이메일로 등록된 사용자가 없습니다."

    return render_template("find_username.html")

# 아이디 찾기 완료 화면
@app.route("/find_username_done")
def find_username_done():
    return render_template("find_username_done.html")


# 대시보드
@app.route('/dashboard')
@login_required
def dashboard():
    user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
    projects = mongo.db.projects.find({"members": ObjectId(current_user.id)}).sort("order", 1)

    project_list = []
    for project in projects:
        if "owner" in project:
            project["owner"] = str(project["owner"])
        else:
            project["owner"] = None
        # 카드 수 추가
        card_count = mongo.db.cards.count_documents({"project_id": project["_id"]})
        project["card_count"] = card_count
        project_list.append(project)

    return render_template(
        "dashboard.html",
        user={"_id": str(current_user.id), "username": current_user.username},
        projects=project_list
    )


# 프로젝트 순서 저장
@app.route("/projects/reorder", methods=["POST"])
@login_required
def reorder_projects():
    data = request.get_json()
    order = data.get("order", [])

    for index, project_id in enumerate(order):
        try:
            mongo.db.projects.update_one(
                {"_id": ObjectId(project_id), "members": ObjectId(current_user.id)},
                {"$set": {"order": index}}
            )
        except InvalidId:
            logger.error(f"Invalid project_id: {project_id}")
            continue

    return jsonify({"message": "프로젝트 순서가 업데이트되었습니다."}), 200


# 프로젝트 순서 조회
@app.route("/projects/order", methods=["GET"])
@login_required
def get_project_order():
    projects = mongo.db.projects.find({"members": ObjectId(current_user.id)}).sort("order", 1)
    order = [str(project["_id"]) for project in projects]
    return jsonify({"order": order}), 200


# 프로젝트 생성
@app.route("/projects/create", methods=["POST"])
@login_required
def create_project():
    data = request.get_json()
    if not data or "name" not in data:
        logger.error("Missing project name in request")
        return jsonify({"message": "프로젝트 이름이 필요합니다."}), 400

    try:
        # 기존 프로젝트 수를 조회하여 새 프로젝트의 order 설정
        max_order = mongo.db.projects.find({"members": ObjectId(current_user.id)}).sort("order", -1).limit(1)
        max_order_doc = next(max_order, None)
        max_order_value = max_order_doc["order"] + 1 if max_order_doc else 0

        new_project = {
            "name": data["name"],
            "description": data.get("description", ""),
            "members": [ObjectId(current_user.id)],
            "owner": ObjectId(current_user.id),
            "created_at": datetime.utcnow(),
            "order": max_order_value
        }

        result = mongo.db.projects.insert_one(new_project)
        logger.info(f"Created project: {result.inserted_id}")
        return jsonify({
            "id": str(result.inserted_id),
            "name": new_project["name"]
        }), 201
    except Exception as e:
        logger.error(f"프로젝트 저장 중 오류 발생: {str(e)}")
        return jsonify({"message": "서버 오류가 발생했습니다."}), 500


# 프로젝트 삭제/나가기
@app.route("/projects/<project_id>", methods=["DELETE"])
@login_required
def delete_or_leave_project(project_id):
    try:
        project = mongo.db.projects.find_one({"_id": ObjectId(project_id)})
    except InvalidId:
        logger.error(f"Invalid project_id: {project_id}")
        return jsonify({"error": "유효하지 않은 프로젝트 ID입니다."}), 400

    if not project:
        logger.error(f"Project not found: {project_id}")
        return jsonify({"error": "프로젝트를 찾을 수 없습니다."}), 404

    user_id = ObjectId(current_user.id)

    if project.get("owner") == user_id:
        mongo.db.projects.delete_one({"_id": ObjectId(project_id)})
        mongo.db.cards.delete_many({"project_id": ObjectId(project_id)})
        logger.info(f"Deleted project: {project_id}")
        return jsonify({"message": "프로젝트가 삭제되었습니다."}), 200
    elif user_id in project.get("members", []):
        mongo.db.projects.update_one(
            {"_id": ObjectId(project_id)},
            {"$pull": {"members": user_id}}
        )
        logger.info(f"User {user_id} left project: {project_id}")
        return jsonify({"message": "프로젝트에서 나갔습니다."}), 200

    logger.error(f"User {user_id} has no permission for project: {project_id}")
    return jsonify({"error": "권한이 없습니다."}), 403


# 프로젝트 조회
@app.route("/projects/<project_id>", methods=["GET"])
@login_required
def get_project(project_id):
    try:
        project = mongo.db.projects.find_one({"_id": ObjectId(project_id)})
    except InvalidId:
        logger.error(f"Invalid project_id: {project_id}")
        return jsonify({"message": "유효하지 않은 프로젝트 ID입니다."}), 400

    if project:
        logger.info(f"Retrieved project: {project_id}")
        return jsonify({"id": str(project["_id"]), "name": project["name"]}), 200
    logger.error(f"Project not found: {project_id}")
    return jsonify({"message": "프로젝트를 찾을 수 없습니다."}), 404


# 초대
@app.route('/projects/<project_id>/invite', methods=['POST'])
@login_required
def invite_member(project_id):
    data = request.get_json()
    username = data.get('username')

    try:
        user = mongo.db.users.find_one({"username": username})
        project = mongo.db.projects.find_one({"_id": ObjectId(project_id)})
    except InvalidId:
        logger.error(f"Invalid project_id: {project_id}")
        return jsonify({"message": "유효하지 않은 프로젝트 ID입니다."}), 400

    if not user or not project:
        logger.error(f"User {username} or project {project_id} not found")
        return jsonify({"message": "사용자 또는 프로젝트를 찾을 수 없습니다."}), 404

    if ObjectId(user["_id"]) in project.get("members", []):
        logger.error(f"User {username} already a member of project {project_id}")
        return jsonify({"message": "이미 프로젝트 멤버입니다."}), 400

    if ObjectId(project["_id"]) in user.get("invitations", []):
        logger.error(f"User {username} already invited to project {project_id}")
        return jsonify({"message": "이미 초대된 사용자입니다."}), 400

    mongo.db.users.update_one(
        {"_id": user["_id"]},
        {"$push": {"invitations": project["_id"]}}
    )
    logger.info(f"Sent invitation to {username} for project {project_id}")
    return jsonify({"message": "초대가 전송되었습니다."}), 200


@app.route('/invitations', methods=['GET'])
@login_required
def get_invitations():
    user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
    invitations = list(mongo.db.projects.find({"_id": {"$in": user_data.get("invitations", [])}}))
    logger.info(f"Retrieved {len(invitations)} invitations for user {current_user.id}")
    return jsonify({
        "invitations": [{"id": str(p["_id"]), "name": p["name"]} for p in invitations]
    })


@app.route('/invitations/respond', methods=['POST'])
@login_required
def respond_invitation():
    data = request.get_json()
    try:
        project_id = ObjectId(data.get("project_id"))
    except (InvalidId, TypeError):
        logger.error(f"Invalid project_id in invitation response: {data.get('project_id')}")
        return jsonify({"message": "유효하지 않은 프로젝트 ID입니다."}), 400

    action = data.get("action")

    mongo.db.users.update_one(
        {"_id": ObjectId(current_user.id)},
        {"$pull": {"invitations": project_id}}
    )

    if action == "accept":
        mongo.db.projects.update_one(
            {"_id": project_id},
            {"$addToSet": {"members": ObjectId(current_user.id)}}
        )
        logger.info(f"User {current_user.id} accepted invitation for project {project_id}")
    else:
        logger.info(f"User {current_user.id} declined invitation for project {project_id}")

    return jsonify({"message": f"{action} 처리 완료"}), 200


# 모든 프로젝트의 카드 조회
@app.route("/projects/all/cards", methods=["GET"])
@login_required
def get_all_cards():
    projects = mongo.db.projects.find({"members": ObjectId(current_user.id)})
    project_ids = [project["_id"] for project in projects]

    cards = list(mongo.db.cards.find({"project_id": {"$in": project_ids}}).sort("order", 1))
    logger.info(f"Retrieved {len(cards)} cards for user {current_user.id}")
    return jsonify({
        "cards": [{
            "id": str(card["_id"]),
            "title": card["title"],
            "description": card["description"],
            "status": card["status"],
            "project_id": str(card["project_id"]),
            "created_by": str(card["created_by"]),
            "created_at": card["created_at"].isoformat(),
            "order": card.get("order", 0)
        } for card in cards]
    }), 200


# 프로젝트별 카드 수 조회
@app.route("/projects/all/cards/counts", methods=["GET"])
@login_required
def get_card_counts():
    projects = mongo.db.projects.find({"members": ObjectId(current_user.id)})
    counts = {}

    for project in projects:
        project_id = str(project["_id"])
        count = mongo.db.cards.count_documents({"project_id": project["_id"]})
        counts[project_id] = count

    logger.info(f"Retrieved card counts for user {current_user.id}")
    return jsonify({"counts": counts}), 200


# 카드 이동
@app.route("/projects/<project_id>/cards/move", methods=["POST"])
@login_required
def move_card(project_id):
    data = request.get_json()
    card_id = data.get("cardId")
    target_project_id = data.get("projectId")
    order = data.get("order", [])

    logger.info(f"Received move request: card {card_id} to project {target_project_id} with order: {order}")

    # 입력 데이터 검증
    if not card_id or not target_project_id or not order:
        logger.error("Missing required fields in move request")
        return jsonify({"message": "cardId, projectId, order는 필수입니다."}), 400

    try:
        target_project_id = ObjectId(target_project_id)
    except InvalidId:
        logger.error(f"Invalid target_project_id: {target_project_id}")
        return jsonify({"message": "유효하지 않은 프로젝트 ID입니다."}), 400

    try:
        card_id = ObjectId(card_id)
    except InvalidId:
        logger.error(f"Invalid card_id: {card_id}")
        return jsonify({"message": "유효하지 않은 카드 ID입니다."}), 400

    project = mongo.db.projects.find_one({"_id": target_project_id})
    if not project:
        logger.error(f"Project not found: {target_project_id}")
        return jsonify({"message": "프로젝트를 찾을 수 없습니다."}), 404

    if ObjectId(current_user.id) not in project.get("members", []):
        logger.error(f"User {current_user.id} not a member of project {target_project_id}")
        return jsonify({"message": "권한이 없습니다."}), 403

    card = mongo.db.cards.find_one({"_id": card_id})
    if not card:
        logger.error(f"Card not found: {card_id}")
        return jsonify({"message": "카드를 찾을 수 없습니다."}), 404

    # order 배열의 유효성 검사
    for cid in order:
        try:
            cid_obj = ObjectId(cid)
        except InvalidId:
            logger.error(f"Invalid card ID in order: {cid}")
            return jsonify({"message": f"유효하지 않은 카드 ID: {cid}"}), 400
        if not mongo.db.cards.find_one({"_id": cid_obj, "project_id": target_project_id}):
            logger.error(f"Card {cid} not found in project {target_project_id}")
            return jsonify({"message": f"프로젝트에 속하지 않은 카드 ID: {cid}"}), 400

    try:
        with mongo.cx.start_session() as session:
            with session.start_transaction():
                # 카드의 프로젝트 ID 업데이트
                mongo.db.cards.update_one(
                    {"_id": card_id},
                    {"$set": {"project_id": target_project_id}},
                    session=session
                )

                # 카드 순서 업데이트
                for index, cid in enumerate(order):
                    mongo.db.cards.update_one(
                        {"_id": ObjectId(cid), "project_id": target_project_id},
                        {"$set": {"order": index}},
                        session=session
                    )

        logger.info(f"Card {card_id} moved to project {target_project_id} successfully")
        return jsonify({"message": "카드가 이동되었습니다."}), 200
    except PyMongoError as e:
        logger.error(f"Database error during card move: {str(e)}")
        return jsonify({"message": "데이터베이스 오류가 발생했습니다.", "error": str(e)}), 500
    except Exception as e:
        logger.error(f"Unexpected error during card move: {str(e)}")
        return jsonify({"message": "서버 오류가 발생했습니다.", "error": str(e)}), 500


# 카드 생성
@app.route("/projects/<project_id>/cards", methods=["POST"])
@login_required
def create_card(project_id):
    data = request.get_json()
    if not data or "title" not in data:
        logger.error("Missing card title in request")
        return jsonify({"message": "카드 제목이 필요합니다."}), 400

    try:
        project_id = ObjectId(project_id)
    except InvalidId:
        logger.error(f"Invalid project_id: {project_id}")
        return jsonify({"message": "유효하지 않은 프로젝트 ID입니다."}), 400

    project = mongo.db.projects.find_one({"_id": project_id})
    if not project:
        logger.error(f"Project not found: {project_id}")
        return jsonify({"message": "프로젝트를 찾을 수 없습니다."}), 404

    if ObjectId(current_user.id) not in project.get("members", []):
        logger.error(f"User {current_user.id} not a member of project {project_id}")
        return jsonify({"message": "권한이 없습니다."}), 403

    try:
        # 기존 카드의 최대 order 값을 조회
        max_order_doc = mongo.db.cards.find({"project_id": project_id}).sort("order", -1).limit(1)
        max_order_doc = next(max_order_doc, None)
        max_order = max_order_doc["order"] + 1 if max_order_doc else 0

        new_card = {
            "project_id": project_id,
            "title": data["title"],
            "description": data.get("description", ""),
            "created_by": ObjectId(current_user.id),
            "created_at": datetime.utcnow(),
            "status": "todo",
            "order": max_order
        }

        result = mongo.db.cards.insert_one(new_card)
        logger.info(f"Created card: {result.inserted_id} in project {project_id}")
        return jsonify({
            "id": str(result.inserted_id),
            "title": new_card["title"],
            "description": new_card["description"],
            "status": new_card["status"],
            "project_id": str(new_card["project_id"]),
            "order": new_card["order"]
        }), 201
    except Exception as e:
        logger.error(f"카드 저장 중 오류 발생: {str(e)}")
        return jsonify({"message": "서버 오류가 발생했습니다.", "error": str(e)}), 500


# 카드 삭제
@app.route("/projects/<project_id>/cards/<card_id>", methods=["DELETE"])
@login_required
def delete_card(project_id, card_id):
    try:
        project_id = ObjectId(project_id)
        card_id = ObjectId(card_id)
    except InvalidId:
        logger.error(f"Invalid project_id or card_id: {project_id}, {card_id}")
        return jsonify({"message": "유효하지 않은 프로젝트 또는 카드 ID입니다."}), 400

    project = mongo.db.projects.find_one({"_id": project_id})
    if not project:
        logger.error(f"Project not found: {project_id}")
        return jsonify({"message": "프로젝트를 찾을 수 없습니다."}), 404

    if ObjectId(current_user.id) not in project.get("members", []):
        logger.error(f"User {current_user.id} not a member of project {project_id}")
        return jsonify({"message": "권한이 없습니다."}), 403

    card = mongo.db.cards.find_one({
        "_id": card_id,
        "project_id": project_id
    })

    if not card:
        logger.error(f"Card not found: {card_id}")
        return jsonify({"message": "카드를 찾을 수 없습니다."}), 404

    mongo.db.cards.delete_one({"_id": card_id})
    logger.info(f"Deleted card: {card_id} from project {project_id}")
    return jsonify({"message": "카드가 삭제되었습니다."}), 200


# 프로젝트의 모든 카드 조회
@app.route("/projects/<project_id>/cards", methods=["GET"])
@login_required
def get_project_cards(project_id):
    try:
        project_id = ObjectId(project_id)
    except InvalidId:
        logger.error(f"Invalid project_id: {project_id}")
        return jsonify({"message": "유효하지 않은 프로젝트 ID입니다."}), 400

    project = mongo.db.projects.find_one({"_id": project_id})
    if not project:
        logger.error(f"Project not found: {project_id}")
        return jsonify({"message": "프로젝트를 찾을 수 없습니다."}), 404

    if ObjectId(current_user.id) not in project.get("members", []):
        logger.error(f"User {current_user.id} not a member of project {project_id}")
        return jsonify({"message": "권한이 없습니다."}), 403

    cards = list(mongo.db.cards.find({"project_id": project_id}).sort("order", 1))
    logger.info(f"Retrieved {len(cards)} cards for project {project_id}")
    return jsonify({
        "cards": [{
            "id": str(card["_id"]),
            "title": card["title"],
            "description": card["description"],
            "status": card["status"],
            "project_id": str(card["project_id"]),
            "created_by": str(card["created_by"]),
            "created_at": card["created_at"].isoformat(),
            "order": card.get("order", 0)
        } for card in cards]
    }), 200


# 카드 상태 업데이트
@app.route("/projects/<project_id>/cards/<card_id>/status", methods=["PUT"])
@login_required
def update_card_status(project_id, card_id):
    data = request.get_json()
    if not data or "status" not in data:
        logger.error("Missing status in request")
        return jsonify({"message": "상태 정보가 필요합니다."}), 400

    try:
        project_id = ObjectId(project_id)
        card_id = ObjectId(card_id)
    except InvalidId:
        logger.error(f"Invalid project_id or card_id: {project_id}, {card_id}")
        return jsonify({"message": "유효하지 않은 프로젝트 또는 카드 ID입니다."}), 400

    project = mongo.db.projects.find_one({"_id": project_id})
    if not project:
        logger.error(f"Project not found: {project_id}")
        return jsonify({"message": "프로젝트를 찾을 수 없습니다."}), 404

    if ObjectId(current_user.id) not in project.get("members", []):
        logger.error(f"User {current_user.id} not a member of project {project_id}")
        return jsonify({"message": "권한이 없습니다."}), 403

    card = mongo.db.cards.find_one({
        "_id": card_id,
        "project_id": project_id
    })

    if not card:
        logger.error(f"Card not found: {card_id}")
        return jsonify({"message": "카드를 찾을 수 없습니다."}), 404

    mongo.db.cards.update_one(
        {"_id": card_id},
        {"$set": {"status": data["status"]}}
    )
    logger.info(f"Updated status of card {card_id} to {data['status']}")
    return jsonify({"message": "카드 상태가 업데이트되었습니다."}), 200


# 카드 순서 업데이트
@app.route('/projects/<project_id>/cards/reorder', methods=['POST'])
@login_required
def reorder_cards(project_id):
    try:
        project_id = ObjectId(project_id)
    except InvalidId:
        logger.error(f"Invalid project_id: {project_id}")
        return jsonify({'error': '유효하지 않은 프로젝트 ID입니다.'}), 400

    project = mongo.db.projects.find_one({"_id": project_id})
    if not project:
        logger.error(f"Project not found: {project_id}")
        return jsonify({'error': '프로젝트를 찾을 수 없습니다.'}), 404

    if ObjectId(current_user.id) not in project.get("members", []):
        logger.error(f"User {current_user.id} not a member of project {project_id}")
        return jsonify({'error': '권한이 없습니다.'}), 403

    data = request.get_json()
    order = data.get('order', [])

    if not order:
        logger.error("Empty order array in reorder request")
        return jsonify({'error': '카드 순서 배열이 비어 있습니다.'}), 400

    # order 배열의 유효성 검사
    for card_id in order:
        try:
            card_id_obj = ObjectId(card_id)
        except InvalidId:
            logger.error(f"Invalid card_id: {card_id}")
            return jsonify({'error': f'유효하지 않은 카드 ID: {card_id}'}), 400
        card = mongo.db.cards.find_one({"_id": card_id_obj, "project_id": project_id})
        if not card:
            logger.error(f"Card {card_id} not found in project {project_id}")
            return jsonify({'error': f'프로젝트에 속하지 않은 카드 ID: {card_id}'}), 400

    try:
        with mongo.cx.start_session() as session:
            with session.start_transaction():
                for index, card_id in enumerate(order):
                    mongo.db.cards.update_one(
                        {"_id": ObjectId(card_id), "project_id": project_id},
                        {"$set": {"order": index}},
                        session=session
                    )

        logger.info(f"Card order updated for project {project_id}: {order}")
        return jsonify({'message': '카드 순서가 업데이트되었습니다.'}), 200
    except PyMongoError as e:
        logger.error(f"Database error during card reorder: {str(e)}")
        return jsonify({'error': '데이터베이스 오류가 발생했습니다.', 'details': str(e)}), 500
    except Exception as e:
        logger.error(f"Unexpected error during card reorder: {str(e)}")
        return jsonify({'error': '서버 오류가 발생했습니다.', 'details': str(e)}), 500


# 카드 수정
@app.route("/projects/<project_id>/cards/<card_id>", methods=["PUT"])
@login_required
def update_card(project_id, card_id):
    data = request.get_json()
    if not data or "title" not in data:
        logger.error("Missing card title in request")
        return jsonify({"message": "카드 제목이 필요합니다."}), 400

    try:
        project_id = ObjectId(project_id)
        card_id = ObjectId(card_id)
    except InvalidId:
        logger.error(f"Invalid project_id or card_id: {project_id}, {card_id}")
        return jsonify({"message": "유효하지 않은 프로젝트 또는 카드 ID입니다."}), 400

    project = mongo.db.projects.find_one({"_id": project_id})
    if not project:
        logger.error(f"Project not found: {project_id}")
        return jsonify({"message": "프로젝트를 찾을 수 없습니다."}), 404

    if ObjectId(current_user.id) not in project.get("members", []):
        logger.error(f"User {current_user.id} not a member of project {project_id}")
        return jsonify({"message": "권한이 없습니다."}), 403

    card = mongo.db.cards.find_one({
        "_id": card_id,
        "project_id": project_id
    })

    if not card:
        logger.error(f"Card not found: {card_id}")
        return jsonify({"message": "카드를 찾을 수 없습니다."}), 404

    update_data = {
        "title": data["title"],
        "description": data.get("description", "")
    }

    mongo.db.cards.update_one(
        {"_id": card_id},
        {"$set": update_data}
    )
    logger.info(f"Updated card: {card_id} in project {project_id}")
    return jsonify({"message": "카드가 수정되었습니다."}), 200


if __name__ == "__main__":
    app.run(debug=True)