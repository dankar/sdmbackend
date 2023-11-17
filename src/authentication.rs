use axum::{
    extract::State,
    middleware::Next,
    http::Request,
    response::{Redirect, Response, IntoResponse},
    Form,
    http::StatusCode,
};
use axum_session::{
    Session, SessionNullPool
};
use log::info;
use crate::card_verifier;
use crate::server_settings::ServerSettings;

pub async fn ntag_auth_handler(
    session: Session<SessionNullPool>,
    State(server_settings): State<ServerSettings>,
    optional_sdmdata: Option<Form<sdm::SdmData>>,
) -> Result<Redirect, (StatusCode, Response)> {
    info!("Got NTAG request");

    if let Some(sdmdata) = optional_sdmdata {
        match card_verifier::verify_card(&server_settings, &sdmdata) {
            Ok(uid) => {
                session.set("auth", 1);
                session.set("card_uid", uid);
                Ok(Redirect::to(&server_settings.secret_files))
            }
            Err(e) => Err((StatusCode::UNAUTHORIZED, e.into_response())),
        }
    }
    else
    {
        Err((StatusCode::UNAUTHORIZED, "You must blip the thing".into_response()))
    }
}

pub async fn check_auth<B>(
    session: Session<SessionNullPool>,
    req: Request<B>,
    next: Next<B>,
) -> Result<impl IntoResponse, (StatusCode, Response)> {

    let auth = session.get("auth").unwrap_or(0);
    if auth == 1 {
        Ok(next.run(req).await)
    } else {
        Err((StatusCode::UNAUTHORIZED, "Access denied".into_response()))
    }
}
