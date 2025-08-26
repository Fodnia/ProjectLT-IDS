# LT-IDS

Lightweight Tower Defense-based Intrusion Detection System is an intrusion detection system based on implementation of tower-defense model for threat detection alongside machine learning to create a lightweight and effective system for detecting threats.

This IDS was tested on Debian 12, Ubuntu 24.04 LTS, and Raspberry Pi OS Bookworm.

## Features
- Tower defense-based threat detection model.
- ML-powered classification.
- Lightweight design suitable for Raspberry Pi.
- Real-time/batch packet capture and analysis.

## Architecture
In this example, this IDS uses a distributed architecture:
- First machine: Captures network traffic using Suricata and tcpdump.
- Second machine: Processes captured data and performs threat detection.

## Installation

### First machine

Use the package manager to install requirement dependencies.

```bash
sudo apt update
sudo apt -y upgrade
sudo apt install -y suricata tcpdump openssh-client
```

To setup `suricata` for the first time or update the change in `suricata` file.

```bash
sudo suricata-update
sudo systemctl restart suricata
sudo suricata -T
```

In case of `suricata -T` throw an error, the rules may locate in `/var/lib/suricata/rules`. To change rules path, open `/etc/suricata/suricata.yaml` and find `default-rule-path`. After that, change to `/var/lib/suricata/rules`.

Highly recommended to setup settings in the `suricata.yaml` first before running. Especially in the step 3 of the file.
For example,

```yaml
# Linux high speed capture support
af-packet:
  - interface: eth0 # Change to match the machine interface.
```

### Second machine

Use `pip` to install dependencies.

```bash
pip install dpkt pandas numpy joblib scikit-learn
```

## Usage

### First machine

First, run the `suricata`.
For example, using the interface `eth0`.

```bash
sudo suricata -c suricata.yaml -D -i eth0
```

Next, open `capture.sh` and edit the configuration section in the file.

Finally, run `capture.sh` to capture network packets. Note: Remote file transfer code has been removed from this version to maintain code authorship integrity. Please use `scp` or similar tools to transfer captured files between machines.

```bash
sudo sh ./capture.sh
```

### Second machine

In Python, run `convert.py` to convert `.pcap` to `.csv`.
```bash
convert.py [-h] --pcap PCAP --output OUTPUT [--verbose]

PCAP to CSV

options:
  -h, --help       show this help message and exit
  --pcap PCAP      Input .pcap
  --output OUTPUT  Output .csv
  --verbose
```

For example,

```bash
python ./convert.py --pcap ~/capture0 --output ~/example.csv
```

In Python, run `load_model.py` to predict the attack.

```bash
load_model.py [-h] --csv CSV --model MODEL --output OUTPUT

options:
  -h, --help       show this help message and exit
  --csv CSV        input .csv
  --model MODEL    trained .joblib model
  --output OUTPUT  output .json
```

For example,

```bash
python ./load_model.py --csv ./example.csv --model ./dtthree_ids_trained.joblib --output example.json
```

## Model Training (Optional)

The included `dtthree_ids_trained.joblib` model was trained on the CIC-IDS2017 dataset. If you want to retrain the model or train with your own data:

### Dataset
- The dataset available from: [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- Download the CSV files from the website.
- The model uses 20 specific network traffic features for classification.
- If you use this dataset, please cite:
> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, January 2018.

### Training
First, obtain the CIC-IDS2017 dataset (or prepare your own dataset with the same features).

Second, update the path in `ids_trainer.py` or `ids_trainer.ipynb`:
   ```python
   files = glob.glob("/content/drive/MyDrive/CSV2017/*.csv")  # Change this path
   ```
   
Finally, in Python, run `ids_trainer.py` or `ids_trainer.ipynb` to train the model.
For example,

```bash
python ids_trainer.py
```
