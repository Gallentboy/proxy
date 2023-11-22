use std::cell::RefCell;
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::process::exit;
use std::str::FromStr;
use std::sync::Mutex;

use hyper::{Body, Client, HeaderMap, Request, Response, Server, StatusCode, Uri};
use hyper::body::HttpBody;
use hyper::body::Buf;
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::{make_service_fn, service_fn};
use hyper_tls::HttpsConnector;
use lazy_static::lazy_static;

type HttpClient = Client<hyper::client::HttpConnector>;
type HttpsClient = Client<HttpsConnector<hyper::client::HttpConnector>>;
type GenericError = Box<dyn std::error::Error + Send + Sync>;

const PROXY_TARGET: &str = "x-proxy-target";
const DEFAULT_PORT: u16 = 4225;

fn build_https_client() -> HttpsClient {
    let https = HttpsConnector::new();
    return Client::builder().build::<_, Body>(https);
}

fn build_http_client() -> HttpClient {
    Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build_http()
}

lazy_static! {
    static ref HTTP_CLIENT: HttpClient = build_http_client();

    static ref HTTPS_CLIENT : HttpsClient = build_https_client();

    static ref OPTIONS_HEADERS: Mutex<RefCell<HashSet<String>>> = Mutex::new(RefCell::new(HashSet::new()));
}

fn init_options_headers() {
    OPTIONS_HEADERS.lock().unwrap().borrow_mut().insert(PROXY_TARGET.to_string());
}

fn add_options_headers(src: Vec<String>) {
    OPTIONS_HEADERS.lock().unwrap().borrow_mut().extend(src)
}


fn main() {
    init_options_headers();
    let args: Vec<String> = std::env::args()
        .skip(1)
        .collect();
    let port;
    if args.is_empty() {
        port = DEFAULT_PORT;
    } else {
        port = args.first()
            .map(|it| {
                it.parse::<u16>().unwrap_or(DEFAULT_PORT)
            })
            .unwrap_or(DEFAULT_PORT);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    let _enter_guard = rt.enter();
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let make_service = make_service_fn(move |_| {
        async move {
            Ok::<_, Infallible>(service_fn(move |req| async {
                let uri = req.uri().to_string();
                let res = proxy(req).await.unwrap_or_else(|e| {
                    let s = format!("请求[{}]处理失败: {}", uri, e.to_string());
                    Response::builder()
                        .status(500)
                        .body(Body::from(s))
                        .unwrap()
                });
                Ok(res) as Result<Response<Body>, GenericError>
            }
            ))
        }
    });

    let server = Server::try_bind(&addr)
        .map_err(|e| {
            eprintln!("绑定地址失败: {}", e);
            exit(-1);
        })
        .unwrap()
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service);

    println!("Listening on http://{}", addr);
    match rt.block_on(async {
        server.await
    }) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("服务启动失败: {}", e.to_string());
        }
    }
}

fn get_options_headers(headers: &str) -> String {
    let s = OPTIONS_HEADERS.lock().unwrap()
        .borrow()
        .iter()
        .map(|it| it.as_str())
        .collect::<Vec<&str>>()
        .join(", ");
    if headers.is_empty() {
        return s;
    }
    let vec = vec![s, headers.to_string(), "content-type".to_string()];
    let mut set = HashSet::new();
    set.extend(vec);
    set.iter().map(|it| it.as_str()).collect::<Vec<&str>>().join(", ")
}

async fn handle_add_options_header_request(req: Request<Body>) -> Result<Response<Body>, GenericError> {
    let origin = get_origin(req.headers()).unwrap_or("*".to_string());
    let method = req.method().as_str().to_string();
    let whole_body = hyper::body::aggregate(req).await?;
    let data: Vec<String> = serde_json::from_reader(whole_body.reader())?;
    add_options_headers(data);
    let mut response = Response::builder()
        .status(204)
        .body(Body::empty())?;
    modify_response_headers(response.headers_mut(),
                            &origin,
                            &method,
                            "");
    Ok(response)
}

async fn proxy(req: Request<Body>) -> Result<Response<Body>, GenericError> {
    let origin = get_origin(req.headers()).unwrap_or("*".to_string());
    let exposed_headers = get_exposed_headers(req.headers());
    let method = req.method().as_str().to_string();
    let allow_headers = req.headers()
        .iter()
        .map(|(k, _)| k.as_str()).collect::<Vec<&str>>().join(", ");
    if method.eq_ignore_ascii_case("options") {
        let mut response = Response::new(Body::empty());
        let headers = response.headers_mut();
        headers.insert(HeaderName::from_static("access-control-allow-headers"),
                       HeaderValue::from_str(&get_options_headers(&allow_headers)).unwrap());
        headers.insert(HeaderName::from_static("access-control-allow-origin"),
                       HeaderValue::from_str(origin.as_str()).unwrap());
        headers.insert(HeaderName::from_static("access-control-allow-credentials"),
                       HeaderValue::from_static("true"));
        headers.insert(HeaderName::from_static("access-control-allow-methods"),
                       // HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE"));
                       HeaderValue::from_static("POST"));
        let (mut parts, body) = response.into_parts();
        parts.status = StatusCode::OK;
        return Ok(Response::from_parts(parts, body));
    }

    if req.uri().path().ends_with("/addOptionsHeaders") {
        return handle_add_options_header_request(req).await;
    }

    let proxy_target;
    match get_proxy_target(req.headers()) {
        None => {
            return match Response::builder()
                .status(500)
                .header(HeaderName::from_static("content-type"),
                        HeaderValue::from_static("text/plain"))
                .body(Body::from("未指定代理目标")) {
                Ok(mut res) => {
                    modify_response_headers(res.headers_mut(),
                                            &origin, &method, exposed_headers);
                    Ok(res)
                }
                Err(e) => {
                    Err(GenericError::from(e))
                }
            };
        }
        Some(target) => { proxy_target = target.to_string(); }
    }
    let (mut parts, body) = req.into_parts();
    if let Some(path_and_query) = parts.uri.path_and_query() {
        parts.uri = Uri::from_str(&format!("{}/{}", proxy_target, path_and_query.as_str()))
            .map_err(|e| e.to_string())?;
    } else {
        parts.uri = Uri::from_str(proxy_target.as_str()).map_err(|e| e.to_string())?;
    }
    let scheme_str = parts.uri.scheme_str().unwrap_or("").to_string();
    let mut request = Request::from_parts(parts, body);
    modify_request_headers(request.headers_mut());
    let result = if scheme_str.eq_ignore_ascii_case("https") {
        HTTPS_CLIENT.clone().request(request).await
    } else {
        HTTP_CLIENT.clone().request(request).await
    };
    result.map(|mut it| {
        modify_response_headers(it.headers_mut(),
                                origin.as_str(),
                                method.as_str(),
                                exposed_headers);
        it
    })
        .map_err(|e| GenericError::from(e))
}

fn show_headers(headers: &HeaderMap<HeaderValue>) {
    for (k, v) in headers {
        println!("==> k: {}, v: {}", k.as_str(), v.to_str().unwrap_or(""));
    }
}

fn get_proxy_target(headers: &HeaderMap<HeaderValue>) -> Option<&str> {
    headers.get(HeaderName::from_static(PROXY_TARGET))
        .map(|it| it.to_str().unwrap_or(""))
}

fn modify_request_headers(headers: &mut HeaderMap<HeaderValue>) {
    headers.remove(HeaderName::from_static(PROXY_TARGET));
    headers.remove(HeaderName::from_static("sec-fetch-mode"));
    headers.remove(HeaderName::from_static("sec-fetch-site"));
    headers.remove(HeaderName::from_static("sec-fetch-dest"));
    headers.insert(HeaderName::from_static("host"),
                   HeaderValue::from_static("www.baidu.com"));
    headers.insert(HeaderName::from_static("user-agent"),
                   HeaderValue::from_static("gallentboy/reverse-proxy"));
}

fn modify_response_headers<S: AsRef<str>>(headers: &mut HeaderMap<HeaderValue>,
                                          origin: &str,
                                          method: &str,
                                          exposed_headers: S) {
    headers.insert(HeaderName::from_static("access-control-allow-origin"),
                   HeaderValue::from_str(origin).unwrap());
    headers.insert(HeaderName::from_static("access-control-allow-credentials"),
                   HeaderValue::from_static("true"));
    headers.insert(HeaderName::from_static("access-control-allow-methods"),
                   HeaderValue::from_str(method).unwrap());
    headers.insert(HeaderName::from_static("access-control-expose-headers"),
                   HeaderValue::from_str(exposed_headers.as_ref()).unwrap());
}

fn get_origin(headers: &HeaderMap) -> Option<String> {
    for (k, v) in headers {
        if k.as_str().eq_ignore_ascii_case("origin") {
            return v.to_str().map(|it| Some(it.to_string()))
                .unwrap_or(None);
        }
    }
    return None;
}

#[inline(always)]
fn get_exposed_headers(headers: &HeaderMap) -> String {
    headers.iter()
        .filter(|(k, _)| !k.as_str().eq_ignore_ascii_case(PROXY_TARGET))
        .map(|(k, _v)| k.as_str())
        .collect::<Vec<&str>>()
        .join(", ")
}



