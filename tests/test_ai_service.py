from appsec_discovery.services import ScanService
import pytest

from huggingface_hub import snapshot_download
from huggingface_hub import hf_hub_download

import os
from pathlib import Path

from llama_cpp import Llama
from openai import OpenAI


def test_ai_service_config_load():

    test_folder = str(Path(__file__).resolve().parent)
    config_file = os.path.join(test_folder, "config_samples/ai_conf_llama.yaml")

    with open(config_file, 'r') as conf_file:
        scan_service_llama = ScanService(source_folder="some", conf_file=conf_file)

    score_config_llama = scan_service_llama.config

    assert score_config_llama.ai_local is not None

    assert score_config_llama.ai_local.model_id == "mradermacher/Llama-3.2-3B-Instruct-uncensored-GGUF"

    assert "security bot" in score_config_llama.ai_local.system_prompt

# for run this tests: export ENV=local in container cli

def test_ai_service_update_local_llama_8b():

    if os.getenv("ENV") != "local":
        pytest.skip("This test runs only in local environment")

    test_folder = str(Path(__file__).resolve().parent)
    config_file = os.path.join(test_folder, "config_samples/ai_conf_llama_8b.yaml")

    with open(config_file, 'r') as conf_file:
        scan_service = ScanService(source_folder="some", conf_file=conf_file)

    hf_hub_download(repo_id=scan_service.config.ai_local.model_id, filename=scan_service.config.ai_local.gguf_file, cache_dir=scan_service.config.ai_local.model_folder)
    
    assert 1==1

def test_ai_service_update_local_llama():

    if os.getenv("ENV") != "local":
        pytest.skip("This test runs only in local environment")

    test_folder = str(Path(__file__).resolve().parent)
    config_file = os.path.join(test_folder, "config_samples/ai_conf_llama.yaml")

    with open(config_file, 'r') as conf_file:
        scan_service = ScanService(source_folder="some", conf_file=conf_file)

    hf_hub_download(repo_id=scan_service.config.ai_local.model_id, filename=scan_service.config.ai_local.gguf_file, cache_dir=scan_service.config.ai_local.model_folder)
    
    assert 1==1

def test_ai_service_update_local_vikhr():

    if os.getenv("ENV") != "local":
        pytest.skip("This test runs only in local environment")

    test_folder = str(Path(__file__).resolve().parent)
    config_file = os.path.join(test_folder, "config_samples/ai_conf_vikhr_7b.yaml")

    with open(config_file, 'r') as conf_file:
        scan_service = ScanService(source_folder="some", conf_file=conf_file)

    hf_hub_download(repo_id=scan_service.config.ai_local.model_id, filename=scan_service.config.ai_local.gguf_file, cache_dir=scan_service.config.ai_local.model_folder)
    
    assert 1==1

def test_ai_service_llama_local():

    if os.getenv("ENV") != "local":
        pytest.skip("This test runs only in local environment")

    test_folder = str(Path(__file__).resolve().parent)
    config_file = os.path.join(test_folder, "config_samples/ai_conf_llama_8b.yaml")

    samples_folder = os.path.join(test_folder, "ai_samples/code_objects")

    with open(config_file, 'r') as conf_file:
        scan_service = ScanService(source_folder=samples_folder, conf_file=conf_file)
   
    score_config = scan_service.config

    scanned_objects = scan_service.scan_folder()

    assert score_config.ai_local is not None
    assert score_config.ai_local.model_id == "mradermacher/Llama-3.2-3B-Instruct-uncensored-GGUF"

    assert scanned_objects[1].fields["Input.User.email"].field_name == "Input.User.email"
    assert scanned_objects[1].fields["Input.User.email"].severity == "medium"  
    assert "llm" in scanned_objects[1].fields["Input.User.email"].tags

def test_ai_service_vikhr_local():

    if os.getenv("ENV") != "local":
        pytest.skip("This test runs only in local environment")

    test_folder = str(Path(__file__).resolve().parent)
    config_file = os.path.join(test_folder, "config_samples/ai_conf_vikhr_7b.yaml")

    samples_folder = os.path.join(test_folder, "ai_samples/code_objects")

    with open(config_file, 'r') as conf_file:
        scan_service = ScanService(source_folder=samples_folder, conf_file=conf_file)
   
    score_config = scan_service.config

    scanned_objects = scan_service.scan_folder()

    assert score_config.ai_local is not None
    assert score_config.ai_local.model_id == "Neurogen/Vikhr-Llama3.1-8B-Instruct-R-21-09-24-Q4_K_M-GGUF"

    assert scanned_objects[1].fields["Input.User.email"].field_name == "Input.User.email"
    assert scanned_objects[1].fields["Input.User.email"].severity == "medium"  
    assert "llm-pii" in scanned_objects[1].fields["Input.User.email"].tags


def test_ai_service_deepseek_api():

    if os.getenv("ENV") != "local":
        pytest.skip("This test runs only in local environment")

    test_folder = str(Path(__file__).resolve().parent)
    config_file = os.path.join(test_folder, "config_samples/ai_conf_deepseek.yaml")

    samples_folder = os.path.join(test_folder, "ai_samples/code_objects")

    with open(config_file, 'r') as conf_file:
        scan_service = ScanService(source_folder=samples_folder, conf_file=conf_file)
   
    score_config = scan_service.config

    scanned_objects = scan_service.scan_folder()

    assert score_config.ai_api is not None
    assert score_config.ai_api.model == "deepseek-chat"

    assert scanned_objects[1].fields["input.firstName"].field_name == "input.firstName"
    assert scanned_objects[1].fields["input.firstName"].severity == "high"
    assert "llm-pii" in scanned_objects[1].fields["input.firstName"].tags

def test_ai_service_score_objects_local():

    if os.getenv("ENV") != "local":
        pytest.skip("This test runs only in local environment")

    test_folder = str(Path(__file__).resolve().parent)
    config_file = os.path.join(test_folder, "config_samples/ai_conf_vikhr_7b.yaml")

    samples_folder = os.path.join(test_folder, "ai_samples/code_objects")

    with open(config_file, 'r') as conf_file:
        scan_service = ScanService(source_folder=samples_folder, conf_file=conf_file)
   
    score_config = scan_service.config

    llm = Llama.from_pretrained(
        repo_id=score_config.ai_local.model_id,
        filename=score_config.ai_local.gguf_file,
        verbose=False,
        temperature=0.0,
        cache_dir=score_config.ai_local.model_folder
    )
    
    text = '''
    Object: User
    Field_names:
        id
        full_name,
        first_name,
        last_name,
        music_album,
        address,
        snils,
        inn,
        pan,
        tshirt_size
        password
        auth_token
        user.codeword
        pets_lover
        documet_number
    '''

    system_prompt = ''' You are data security bot, for provided object and it field you must deside does it contain any personal, financial, payment, authorization or other private data with special mesures to store and show.'''
   
    question = '''
    Object name: Orders

    Object type: Table
    
    Field name: pets_lover

    Can contain private data? Answer only 'yes' or 'no',
    '''


    response = llm.create_chat_completion(
      messages = [
          {"role": "system", "content": system_prompt},
          {
              "role": "user",
              "content": question
          }
      ]
    )

    answer = response['choices'][0]["message"]["content"]

    assert 1==1


def test_ai_service_score_objects_api():

    if os.getenv("ENV") != "local":
        pytest.skip("This test runs only in local environment")

    api_key = os.getenv("AI_API_KEY")

    test_folder = str(Path(__file__).resolve().parent)
    config_file = os.path.join(test_folder, "config_samples/ai_conf_deepseek.yaml")

    samples_folder = os.path.join(test_folder, "ai_samples/code_objects")

    with open(config_file, 'r') as conf_file:
        scan_service = ScanService(source_folder=samples_folder, conf_file=conf_file)
   
    score_config = scan_service.config

    client = OpenAI(api_key=api_key, base_url=score_config.ai_api.base_url)

    question = '''
    Object name: Client
    Object type: Table  
    Field name: pets_lover
    Can contain private data? Answer only 'yes' or 'no',
    '''

    response = client.chat.completions.create(
        model=score_config.ai_api.model,
        messages=[
            {"role": "system", "content": score_config.ai_api.system_prompt},
            {"role": "user", "content": question},
        ],
        stream=False
    )

    answer = response.choices[0].message.content

    assert 1==1