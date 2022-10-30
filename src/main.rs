use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context as AnyhowContext, Result};

use axum::body::{boxed, Body};
use axum::extract::Path;
use axum::response::Response as AxumResponse;
use axum::{routing, Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use rcgen::{Certificate, CertificateParams, DistinguishedName};

use tokio::sync::Mutex;
use tokio::time::sleep;

use tracing::{error, info, warn};

use instant_acme::{
    Account, Challenge, ChallengeType, Identifier, KeyAuthorization, LetsEncrypt, NewAccount,
    NewOrder, Order, OrderState, OrderStatus,
};

const MAX_RETRIES: u16 = 12;

#[derive(Clone)]
pub struct ChallengeResponder(Arc<Mutex<HashMap<String, KeyAuthorization>>>);

impl ChallengeResponder {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::default())))
    }

    pub async fn insert_challenge(&self, token: String, key_authz: KeyAuthorization) {
        self.0.lock().await.insert(token, key_authz);
    }

    pub fn into_router(self) -> Router {
        Router::new()
            .route(
                "/.well-known/acme-challenge/:token",
                routing::get(Self::respond),
            )
            .layer(Extension(self))
    }

    async fn respond(
        Extension(responder): Extension<ChallengeResponder>,
        Path(token): Path<String>,
    ) -> AxumResponse {
        let (status_code, body) = if let Some(key_authz) = responder.0.lock().await.get(&token) {
            (200, Body::from(key_authz.as_str().to_owned()))
        } else {
            (404, Body::empty())
        };
        AxumResponse::builder()
            .status(status_code)
            .body(boxed(body))
            .unwrap()
    }
}

pub struct Provision {
    account: Option<Account>,
    responder: ChallengeResponder,
    identifier: String,
}

impl Provision {
    pub fn new(responder: ChallengeResponder, identifier: String) -> Self {
        Self {
            account: None,
            responder,
            identifier,
        }
    }

    async fn create_account() -> Result<Account> {
        Account::create(
            &NewAccount {
                contact: &["mailto:hi@damien.sh"],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            LetsEncrypt::Staging.url(),
        )
        .await
        .context("could not create LetsEncrypt account")
    }

    async fn create_order(account: &Account, identifier: Identifier) -> Result<Order> {
        account
            .new_order(&NewOrder {
                identifiers: &[identifier],
            })
            .await
            .map(|(order, _)| order)
            .context("could not create order")
    }

    fn get_http_challenge<I>(challenges: I) -> Result<Challenge>
    where
        I: IntoIterator<Item = Challenge>,
    {
        challenges
            .into_iter()
            .find(|challenge| challenge.r#type == ChallengeType::Http01)
            .ok_or_else(|| anyhow!("could not find Http01 challenge"))
    }

    async fn wait_for_order(order: &mut Order) -> Result<OrderState> {
        let mut tries = 1;
        let mut delay = Duration::from_millis(100);
        let state = loop {
            sleep(delay).await;
            let state = order.state().await?;
            match state.status {
                OrderStatus::Invalid => {
                    error!(?state, "order ended in invalid state");
                    return Err(anyhow!("order invalid"));
                }
                OrderStatus::Ready => {
                    break state;
                }
                _ => {
                    delay *= 2;
                    tries += 1;
                    if tries > MAX_RETRIES {
                        return Err(anyhow!("could not complete order in time"));
                    } else {
                        info!(?state, tries, "order is not ready, waiting");
                    }
                }
            }
        };
        Ok(state)
    }

    async fn get_certificate_chain(
        mut order: Order,
        cert: &Certificate,
        finalize_url: &str,
    ) -> Result<String> {
        let csr = cert.serialize_request_der()?;
        order
            .finalize(&csr, finalize_url)
            .await
            .context("could not get certificate signed")
    }

    async fn start(self) -> Result<RustlsConfig> {
        let account = match self.account.as_ref() {
            Some(account) => {
                warn!("existing account found");
                account.clone()
            }
            None => {
                info!("no account found, creating one");
                Self::create_account().await?
            }
        };

        info!("successfully retrieved an account");

        let mut order =
            Self::create_order(&account, Identifier::Dns(self.identifier.clone())).await?;

        info!("successfully created an order");

        let state = order.state().await?;

        info!(?state.status, "order status");

        for authz in order.authorizations(&state.authorizations).await.unwrap() {
            info!(?authz.status, ?authz.identifier, "new authorization");

            let challenge = Self::get_http_challenge(authz.challenges)?;

            info!(?challenge.status, "corresponding http challenge");

            let key_authz = order.key_authorization(&challenge);

            info!(?challenge.token, "inserting key authorization");

            self.responder
                .insert_challenge(challenge.token, key_authz)
                .await;

            info!("ready for challenge");

            order.set_challenge_ready(&challenge.url).await?;
        }

        info!("waiting for order to terminate");

        let state = Self::wait_for_order(&mut order).await?;

        info!(?state.status, "order terminated");

        info!("issuing certificate chain");

        let mut params = CertificateParams::new([self.identifier]);
        params.distinguished_name = DistinguishedName::new();
        let cert = Certificate::from_params(params).unwrap();

        let chain = Self::get_certificate_chain(order, &cert, &state.finalize).await?;

        let config = RustlsConfig::from_pem(
            chain.as_bytes().to_owned(),
            cert.serialize_private_key_pem().as_bytes().to_owned(),
        ).await?;

        Ok(config)
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct ServeArgs {
    /// network address to bind the HTTP server to
    #[arg(long, default_value = "0.0.0.0:80")]
    bind_http: SocketAddr,

    /// network address to bind the HTTPS server to
    #[arg(long, default_value = "0.0.0.0:443")]
    bind_https: SocketAddr,

    /// the DNS identifier of this server
    #[arg(long, default_value = "ldn.damien.sh")]
    identifier: String,
}

pub async fn hello() -> &'static str {
    "Hello, world!"
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let ServeArgs { bind_http, bind_https, identifier } = ServeArgs::parse();

    let responder = ChallengeResponder::new();

    let responder_service = responder.clone().into_router().into_make_service();

    let responder_server = tokio::spawn(hyper::Server::bind(&bind_http).serve(responder_service));

    let provision = tokio::spawn(Provision::new(responder, identifier).start());

    tokio::select! {
        res = responder_server => {
            info!("responder server terminated");
            res.unwrap().unwrap();
        },
        res = provision => {
            let config = res.unwrap().unwrap();
            info!("ACME protocol terminated");

            info!(%bind_https, "starting server");
            axum_server::bind_rustls(bind_https, config)
                .serve(Router::new().route("/", routing::get(hello)).into_make_service())
                .await
                .unwrap();
        }
    };

    Ok(())
}
