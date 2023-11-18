use crate::card_verifier;
use crate::server_settings::ServerSettings;
use axum::{
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Redirect},
    Form,
};
use axum_session::{Session, SessionNullPool};
use log::info;

pub async fn ntag_auth_handler(
    session: Session<SessionNullPool>,
    State(server_settings): State<ServerSettings>,
    optional_sdmdata: Option<Form<sdm::SdmData>>,
) -> Redirect {
    info!("Got NTAG request");

    if let Some(sdmdata) = optional_sdmdata {
        if let Ok(uid) = card_verifier::verify_card(&server_settings, &sdmdata) {
            session.set("auth", 1);
            session.set("card_uid", uid);
            return Redirect::to("/secret");
        }
    } 

    return Redirect::to("/static/access-denied.html");
}

pub async fn ntag_logout(session: Session<SessionNullPool>) -> Redirect {
    session.clear();
    Redirect::to("/")
}

pub async fn check_auth<B>(
    session: Session<SessionNullPool>,
    req: Request<B>,
    next: Next<B>,
) -> Result<impl IntoResponse, Redirect> {
    let auth = session.get("auth").unwrap_or(0);
    if auth == 1 {
        Ok(next.run(req).await)
    } else {
        Err(Redirect::to("/static/access-denied.html"))
    }
}
