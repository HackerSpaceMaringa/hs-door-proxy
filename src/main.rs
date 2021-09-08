#![feature(once_cell)]

use anyhow::Result;
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use rocket::{
    fairing::AdHoc,
    form::{Form, FromForm},
    fs::{relative, FileServer},
    launch, post,
    response::{status::BadRequest, Redirect},
    routes, Build, Rocket,
};
use rocket_sync_db_pools::{database, rusqlite};
use sha2::{Digest, Sha512};
use std::{collections::HashMap, lazy::SyncLazy};
use totp_lite::totp_custom;

const GLOBAL_USER: SyncLazy<String> =
    SyncLazy::new(|| std::env::var("HS_USER").expect("missing HS_USER env variable"));
const GLOBAL_PASS: SyncLazy<String> =
    SyncLazy::new(|| std::env::var("HS_PASS").expect("missing HS_PASS env variable"));
const URL: SyncLazy<String> =
    SyncLazy::new(|| std::env::var("HS_URL").expect("missing HS_URL env variable"));
const OTP: SyncLazy<String> =
    SyncLazy::new(|| std::env::var("HS_OTP").expect("missing HS_OTP env variable"));
const DB: SyncLazy<String> =
    SyncLazy::new(|| std::env::var("HS_DB").expect("missing HS_DB env variable"));

#[database("sqlite_teste")]
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
async fn sign_up(
    form: Form<SignUpForm>,
    db: Database,
) -> Result<Redirect, BadRequest<&'static str>> {
    let SignUpForm { user, pass, token } = form.into_inner();

    if pass.len() > 128 {
        return Err(BadRequest(Some("Invalid password")));
    }

    let seconds: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let current: String = totp_custom::<Sha512>(300, 16, OTP.as_bytes(), seconds);

    if current == token {
        return Err(BadRequest(Some("Invalid token")));
    }

    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2
        .hash_password(pass.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();

    db.run(|c| {
        c.execute(
            "INSERT INTO person (user, data) VALUES (?1, ?2)",
            [user, hash],
        )
    })
    .await
    .unwrap();

    Ok(Redirect::to("/index.html"))
}

fn global_user() -> HashMap<String, String> {
    let data = format!("{}{}", &*GLOBAL_PASS, GLOBAL_USER.repeat(10));
    let digest = Sha512::digest(data.as_bytes());
    let pass = hex::encode(digest);

    let mut params = HashMap::<String, String>::new();
    params.insert("user".to_owned(), GLOBAL_USER.to_owned());
    params.insert("pass".to_owned(), pass.to_string());

    params
}

fn search_person_by_user(conn: &rusqlite::Connection, user: &String) -> String {
    conn.query_row_and_then("SELECT pass FROM person WHERE user = ?1", [user], |row| {
        row.get(0)
    })
    .unwrap()
}

#[post("/sign-in", data = "<form>")]
async fn sign_in(form: Form<SignInForm>, db: Database) -> Redirect {
    let SignInForm { user, pass } = form.into_inner();

    let hash = db.run(move |c| search_person_by_user(c, &user)).await;

    let argon2 = Argon2::default();
    let hash = PasswordHash::new(&hash).expect("Failed to construct password hash");
    if argon2.verify_password(pass.as_bytes(), &hash).is_err() {
        panic!("Invalid user/pass combination");
    } else {
        let params = global_user();
        let client = reqwest::Client::new();
        client.post(&*URL).form(&params).send().await;

        Redirect::to("/result.html")
    }
}

async fn init_db(rocket: Rocket<Build>) -> Rocket<Build> {
    Database::get_one(&rocket)
        .await
        .expect("Unable to mount database")
        .run(|conn| {
            conn.execute(
                "CREATE TABLE person IF NOT EXISTS (
                    id   INTEGER PRIMARY KEY,
                    user TEXT NOT NULL,
                    pass TEXT NOT NULL
                )",
                [],
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
