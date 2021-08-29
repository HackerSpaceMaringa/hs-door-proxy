use rocket::form::{Form, FromForm};
use rocket::fs::{relative, FileServer};
use rocket::response::Redirect;
use rocket::{launch, post, routes};
use sha2::{Digest, Sha512};
use std::collections::HashMap;

const URL: &str = env!("HS_URL", "missing HS_URL env variable");

#[derive(FromForm)]
struct SignInForm {
    user: String,
    pass: String,
}

#[post("/sign-in", data = "<form>")]
async fn sign_in(form: Form<SignInForm>) -> Redirect {
    let SignInForm { user, pass } = form.into_inner();
    let data = format!("{}{}", pass, user.repeat(10));
    let digest = Sha512::digest(data.as_bytes());
    let pass = hex::encode(digest);
    println!("pass={}", pass);

    let mut params = HashMap::new();
    params.insert("user", user);
    params.insert("pass", pass);

    let client = reqwest::Client::new();
    client.post(URL).form(&params).send().await;

    Redirect::to("/result.html")
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![sign_in])
        .mount("/", FileServer::from(relative!("static")))
}
