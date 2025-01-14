# DepFusion
DepFusion is a tool to detect dependency confusion vulnerabilities by scanning files like package.json and requirements.txt recursively in directories or repositories, highlighting unregistered dependencies.

# DepFusion: Installation and Usage Guide

### Step 1: Clone the Repository

```
git clone https://github.com/yourusername/DepFusion.git
cd DepFusion
```

### Step 2: Install Dependencies

`pip install -r requirements.txt`

### Step 3: Run the Tool
Use the following commands based on your scan requirements:

#### Analyze a single file:

`python3 depFusion.py -f <path_to_file>`

#### Analyze a directory:

`python3 depFusion.py -d <path_to_directory>`

#### Analyze an entire repository recursively:

`python3 depFusion.py -R <path_to_repository>`

#### Save results to an output file:

`python3 depFusion.py -R <path_to_repository> -o results.json`

