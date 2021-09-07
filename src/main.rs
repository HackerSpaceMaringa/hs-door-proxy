use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rocket::fairing::AdHoc;
use rocket::form::{Form, FromForm};
use rocket::fs::{relative, FileServer};
use rocket::response::Redirect;
use rocket::{launch, post, routes};
use rocket::{Build, Rocket};
use rocket_sync_db_pools::{database, rusqlite};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use totp_lite::totp_custom;

const GLOBAL_USER: &str = env!("HS_USER", "missing HS_USER env variable");
const GLOBAL_PASS: &str = env!("HS_PASS", "missing HS_PASS env variable");
const URL: &str = env!("HS_URL", "missing HS_URL env variable");
const OTP: &str = env!("HS_OTP", "missing HS_OTP env variable");
const DB: &str = env!("HS_DB", "missing HS_DB env variable");

#[database("rusqlite")]
struct Database(rusqlite::Connection);

#[derive(FromForm)]
struct SignInForm {
    user: String,
    pass: String,
}

#[derive(FromForm)]
struct SignUpForm {
    user: String,
    pass: String,
    token: String,
}

#[post("/sign-up", data = "<form>")]
async fn sign_up(form: Form<SignUpForm>, db: Database) -> Redirect {
    let SignUpForm { user, pass, token } = form.into_inner();

    let seconds: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let current: String = totp_custom::<Sha512>(300, 16, OTP.as_bytes(), seconds);

    if current == token {
        panic!("Invalid token");
    }

    if pass.len() > 128 {
        panic!("Invalid password");
    }

    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2
        .hash_password(pass.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();

    db.run(move |conn| {
        conn.execute(
            "INSERT INTO person (user, data) VALUES (?1, ?2)",
            rusqlite::params![user, hash],
        )
        .expect("Failed to save user")
    });

    Redirect::to("/index.html")
}

fn global_user() -> HashMap<String, String> {
    let data = format!("{}{}", GLOBAL_PASS, GLOBAL_USER.repeat(10));
    let digest = Sha512::digest(data.as_bytes());
    let pass = hex::encode(digest);

    let mut params = HashMap::<String, String>::new();
    params.insert("user".to_owned(), GLOBAL_USER.to_owned());
    params.insert("pass".to_owned(), pass.to_string());

    params
}

#[post("/sign-in", data = "<form>")]
async fn sign_in(form: Form<SignInForm>, db: Database) -> Redirect {
    let SignInForm { user, pass } = form.into_inner();

    let hash = db
        .run(|conn| {
            let mut stmt = conn
                .prepare("SELECT pass FROM person WHERE user = ?1")
                .expect("Failed to construct query");
            let mut rows = stmt
                .query(rusqlite::params![user])
                .expect("Failed to execute query");
            let hash = rows.next().expect("Failed to extract row");
            hash
        })
        .await;

    if let None = hash {
        panic!("Invalid user/pass combination");
    }

    let hash = hash.unwrap();
    let hash: String = hash.get(0).expect("Failed to get pass");

    let argon2 = Argon2::default();
    let hash = PasswordHash::new(&hash).expect("Failed to construct password hash");
    if argon2.verify_password(pass.as_bytes(), &hash).is_err() {
        panic!("Invalid user/pass combination");
    }

    // Add Log

    let params = global_user();
    let client = reqwest::Client::new();
    client.post(URL).form(&params).send().await;

    Redirect::to("/result.html")
}

async fn init_db(rocket: Rocket<Build>) -> Rocket<Build> {
    Database::get_one(&rocket)
        .await
        .expect("Unable to mount database")
        .run(|conn| {
            conn.execute(
                "CREATE TABLE person (
                    id   INTEGER PRIMARY KEY,
                    user TEXT NOT NULL,
                    pass TEXT NOT NULL
                )",
                rusqlite::params![],
            )
        })
        .await
        .expect("Unable to create `person` table");

    rocket
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(Database::fairing())
        .attach(AdHoc::on_ignite("init database", init_db))
        .mount("/", routes![sign_up, sign_in])
        .mount("/", FileServer::from(relative!("static")))
}
