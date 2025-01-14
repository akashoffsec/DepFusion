import os
import argparse
import json
import requests
from termcolor import colored
import re

# Define constants
NPM_REGISTRY = "https://registry.npmjs.org/"
PYPI_REGISTRY = "https://pypi.org/pypi/"

def print_logo():
    logo = """
██████╗ ███████╗██████╗ ███████╗██╗   ██╗██╗███████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗██╔════╝██║   ██║██║██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██████╔╝█████╗  ██║   ██║██║█████╗  ██║   ██║██╔██╗ ██║
██╔═══╝ ██╔══╝  ██╔═══╝ ██╔══╝  ╚██╗ ██╔╝██║██╔══╝  ██║   ██║██║╚██╗██║
██║     ███████╗██║     ███████╗ ╚████╔╝ ██║███████╗╚██████╔╝██║ ╚████║
╚═╝     ╚══════╝╚═╝     ╚══════╝  ╚═══╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                       
███████╗██████╗ ███████╗███████╗██╗███╗   ██╗███████╗ ██████╗ ███╗   ██╗
██╔════╝██╔══██╗██╔════╝██╔════╝██║████╗  ██║██╔════╝██╔═══██╗████╗  ██║
█████╗  ██████╔╝█████╗  █████╗  ██║██╔██╗ ██║█████╗  ██║   ██║██╔██╗ ██║
██╔══╝  ██╔═══╝ ██╔══╝  ██╔══╝  ██║██║╚██╗██║██╔══╝  ██║   ██║██║╚██╗██║
███████╗██║     ███████╗██║     ██║██║ ╚████║███████╗╚██████╔╝██║ ╚████║
╚══════╝╚═╝     ╚══════╝╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
    """
    print(colored(logo, "red"))

# Function to check if a dependency is potentially vulnerable
def check_dependency(package_name, registry):
    try:
        if registry == "npm":
            response = requests.get(f"{NPM_REGISTRY}{package_name}")
        elif registry == "pypi":
            response = requests.get(f"{PYPI_REGISTRY}{package_name}/json")
        else:
            return False

        if response.status_code == 404:
            print(colored(f"[VULNERABLE] Package {package_name} not found in public {registry.upper()} registry! Possible for takeover.", "red"))
            return True  # Package not found, potential dependency confusion
        elif response.status_code == 200:
            data = response.json()
            if registry == "npm" and 'time' in data and 'unpublished' in data['time']:
                print(colored(f"[VULNERABLE] Package {package_name} has been unpublished from NPM registry!", "red"))
                return True
            print(colored(f"Package {package_name} found in {registry.upper()} registry.", "green"))
        else:
            print(colored(f"Unexpected status code {response.status_code} for {package_name}.", "yellow"))
        
        return False
    except requests.exceptions.RequestException as e:
        print(colored(f"Error checking {package_name}: {e}", "red"))
        return False

# Function to parse dependencies from various files
def parse_dependencies(file_path):
    vulnerable_dependencies = []
    registry = None
    dependencies = []

    try:
        with open(file_path, "r") as file:
            if file_path.endswith("package.json") or file_path.endswith("package-lock.json"):
                data = json.load(file)
                dependencies = data.get("dependencies", {}).keys()
                registry = "npm"
            elif file_path.endswith("requirements.txt") or file_path.endswith("Pipfile") or file_path.endswith("Pipfile.lock"):
                dependencies = [line.strip().split("==")[0] for line in file if line.strip() and not line.startswith("#")]
                registry = "pypi"
            elif file_path.endswith("yarn.lock"):
                dependencies = re.findall(r'^[^#\n][\w\-]+', file.read(), re.MULTILINE)
                registry = "npm"
            else:
                return vulnerable_dependencies

            for dep in dependencies:
                print(colored(f"Checking dependency: {dep}", "cyan"))
                if check_dependency(dep, registry):
                    vulnerable_dependencies.append(dep)
                    print(colored(f"[!] {dep} is potentially vulnerable!", "yellow"))
    except Exception as e:
        print(colored(f"Error parsing {file_path}: {e}", "red"))

    return vulnerable_dependencies

# Recursive search function
def recursive_search(path, file_types):
    vulnerable_results = {}

    for root, dirs, files in os.walk(path):
        print(colored(f"Searching in: {root}", "blue"))
        for file in files:
            if any(file.endswith(ft) for ft in file_types):
                file_path = os.path.join(root, file)
                print(colored(f"Found file: {file}", "green"))
                vulnerabilities = parse_dependencies(file_path)
                if vulnerabilities:
                    vulnerable_results[file_path] = vulnerabilities

    return vulnerable_results

# Main function
def main():
    print_logo()
    parser = argparse.ArgumentParser(description="DepFusiour: Dependency Confusion Vulnerability Scanner")
    parser.add_argument("-f", "--file", help="Path to the file to analyze")
    parser.add_argument("-d", "--directory", help="Path to the directory to analyze")
    parser.add_argument("-R", "--repository", help="Path to the repository for recursive analysis")
    parser.add_argument("-o", "--output", help="Output file to save the results")

    args = parser.parse_args()

    file_types = ["package.json", "package-lock.json", "yarn.lock", "requirements.txt", "Pipfile", "Pipfile.lock"]
    results = {}

    if args.file:
        if os.path.isfile(args.file):
            print(colored(f"Analyzing file: {args.file}", "cyan"))
            results[args.file] = parse_dependencies(args.file)
        else:
            print(colored(f"File not found: {args.file}", "red"))

    if args.directory:
        if os.path.isdir(args.directory):
            print(colored(f"Analyzing directory: {args.directory}", "cyan"))
            for file in os.listdir(args.directory):
                file_path = os.path.join(args.directory, file)
                if any(file.endswith(ft) for ft in file_types):
                    results[file_path] = parse_dependencies(file_path)
        else:
            print(colored(f"Directory not found: {args.directory}", "red"))

    if args.repository:
        if os.path.isdir(args.repository):
            print(colored(f"Analyzing repository: {args.repository}", "cyan"))
            results = recursive_search(args.repository, file_types)
        else:
            print(colored(f"Repository not found: {args.repository}", "red"))

    # Display results
    for path, vulnerabilities in results.items():
        if vulnerabilities:
            print(colored(f"[VULNERABLE] {path}", "red"))
            for vuln in vulnerabilities:
                print(colored(f"  - {vuln}", "yellow"))

    # Save results to output file
    if args.output:
        try:
            with open(args.output, "w") as outfile:
                json.dump(results, outfile, indent=4)
            print(colored(f"Results saved to {args.output}", "green"))
        except Exception as e:
            print(colored(f"Error saving results: {e}", "red"))

if __name__ == "__main__":
    main()
