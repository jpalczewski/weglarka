//! The generated config pipeline (#212) inside a running daemon: the consumer gets its files before
//! its first start, the worker keeps them current, and `doctor` reports the result.

use crate::common::*;

use std::sync::{Arc, Mutex};

use serde_json::Value;
use weglarka_model::app::{AppSpec, InstanceName};
use weglarka_model::generated::{
    ConfigGenerator, FileName, GeneratedFile, RenderError, RenderInput,
};

struct Rules {
    consumer: InstanceName,
    content: Mutex<String>,
}

impl ConfigGenerator for Rules {
    fn id(&self) -> &'static str {
        "rules"
    }

    fn consumer(&self) -> &InstanceName {
        &self.consumer
    }

    fn render(&self, _: &RenderInput<'_>) -> Result<Vec<GeneratedFile>, RenderError> {
        Ok(vec![GeneratedFile::new(
            FileName::new("rules.yml").unwrap(),
            self.content.lock().unwrap().clone().into_bytes(),
        )])
    }

    fn validate_argv(&self, _: &AppSpec, _: &str) -> Option<Vec<String>> {
        None
    }
}

async fn doctor_check(h: &Harness, id: &str) -> Option<Value> {
    let (_, report) = admin(h, "GET", "/v1/doctor", None).await;
    report["checks"]
        .as_array()?
        .iter()
        .find(|c| c["id"] == id)
        .cloned()
}

#[tokio::test]
async fn the_consumer_gets_its_files_before_the_first_start_and_doctor_reports_them() {
    let generator = Arc::new(Rules {
        consumer: InstanceName::new("idp").unwrap(),
        content: Mutex::new("rules: []\n".into()),
    });
    let h = Builder::new().generator(generator).build().await;
    add(&h, "idp", spec("idp.example.com")).await;
    deployed(&h, "idp").await;

    // The version exists, `current` points at it, and the container mounts the parent read-only.
    let dir = h.root.join("state/generated/idp");
    let current = std::fs::read_link(dir.join("current")).unwrap();
    assert!(current.to_string_lossy().starts_with("v-"), "{current:?}");
    assert_eq!(
        std::fs::read_to_string(dir.join("current/rules.yml")).unwrap(),
        "rules: []\n"
    );
    let mounted = h.fake.created_specs().into_iter().any(|s| {
        s.mounts
            .iter()
            .any(|m| m.target == "/weglarka/generated" && m.read_only)
    });
    assert!(mounted, "the consumer mounts the generated directory");

    let check = doctor_check(&h, "generated.rules")
        .await
        .expect("a generated.rules check");
    let message = check["message"].as_str().unwrap();
    assert!(
        message.contains("idp: live v-") && message.contains("applied v-"),
        "{message}"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn a_daemon_without_generators_reports_nothing_and_mounts_nothing() {
    let h = harness().await;
    add(&h, "idp", spec("idp.example.com")).await;
    deployed(&h, "idp").await;
    assert!(doctor_check(&h, "generated.rules").await.is_none());
    assert!(
        h.fake
            .created_specs()
            .iter()
            .all(|s| s.mounts.iter().all(|m| m.target != "/weglarka/generated"))
    );
    h.running.stop().await;
}
