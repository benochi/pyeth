# Emulated Hardware Device Simulator

This project emulates hardware devices that communicate using different networking protocols. The main program (`main.py`) creates and manages devices, each configured with a specific protocol type. The initial protocol implemented is LLDP, with more protocols planned.

## Project Setup

Follow these steps to set up and run the project in an isolated Python environment.

### Prerequisites

- Python 3.7 or higher
- Virtual environment (`venv`) module

### Installation

1. **Clone the Repository**

   Clone this repository to your local machine:

   ```bash
   git clone <repository_url>
   cd <repository_name>
   ```

### Create a virtual environment

python3 -m venv env

### Activate the virtual environment

#### Max/ Linux

source env/bin/activate

#### Windows

.\env\Scripts\activate

### Install required packages

pip install -r requirements.txt

### Running the program

python main.py

### Run test cases

pytest

### Exit the application isolated environment

deactivate
