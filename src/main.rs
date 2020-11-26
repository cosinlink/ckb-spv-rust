use ckb_types::bytes::Bytes;
use clap::{App, Arg};
use eaglesong::eaglesong;
use serde::{de, Deserialize, Deserializer, Serialize};
use std::{collections::HashSet, env, fmt, fs, marker::PhantomData, path::PathBuf};
const TEST_DATA_DIR: &str = "test-data";

pub struct Loader(PathBuf);

impl Default for Loader {
    fn default() -> Self {
        Self::with_current_dir()
    }
}

impl Loader {
    fn with_current_dir() -> Self {
        let dir = env::current_dir().unwrap();
        let mut base_path = PathBuf::new();
        base_path.push(dir);
        base_path.push(TEST_DATA_DIR);
        Loader(base_path)
    }

    pub fn load_binary(&self, name: &str) -> Bytes {
        let mut path = self.0.clone();
        path.push(name);
        fs::read(path).expect("binary").into()
    }

    pub fn load_data(&self, name: &str) -> serde_json::Value {
        let mut config_path = self.0.clone();
        config_path.push(name);
        let json_str = fs::read_to_string(&config_path).expect("data load failed");
        serde_json::from_str(&json_str).expect("invalid rpc data json")
    }

    pub fn store_test_data<T: Serialize>(&self, filename: &str, test_data: &T) {
        let mut path = self.0.clone();
        path.push(filename);
        let str = serde_json::to_string(test_data).unwrap();
        fs::write(path, str.as_str());
    }
}

fn main() {
    let matches = App::new("eaglesong hash")
        .arg(
            Arg::with_name("path")
                .short("p")
                .help("the eaglesong test input path")
                .takes_value(true),
        )
        .get_matches();

    let test_file = matches
        .value_of("path")
        .unwrap_or("eaglesong_fuzzy_test.json");

    let mut value = Loader::default().load_data(test_file);
    let arr = value["calculateEaglesong"].as_array().unwrap();
    dbg!(arr);

    for item in arr {
        let input_str = item["input"].as_str().unwrap();
        let input = hex::decode(&input_str.as_bytes()[2..98]).unwrap();
        let mut output = [0u8; 32];
        eaglesong(input.as_slice(), &mut output);
        dbg!(hex::encode(output));
    }
}
