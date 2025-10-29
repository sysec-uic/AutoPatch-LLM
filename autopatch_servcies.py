import json
import os
import subprocess

CONFIG = "autopatch_services.json"
SERVICE_CMDS = {
    "fuzzing-service": ["docker", "compose", "up", "-d", "fuzzing-service"],
    "patching-service": ["docker", "compose", "up", "-d", "patching-service"],
    "evaluation-service": ["docker", "compose", "up", "-d", "evaluation-service"],
}


def load():
    if not os.path.exists(CONFIG):
        with open(CONFIG, "w") as f:
            json.dump({}, f)
    with open(CONFIG, "r") as f:
        return json.load(f)


def save(svcs):
    with open(CONFIG, "w") as f:
        json.dump(svcs, f, indent=4)


def show(svcs):
    for name, enabled in svcs.items():
        print(f"{name}: {'ON' if enabled else 'OFF'}")


def toggle(svcs):
    show(svcs)
    c = input("Service name to toggle: ").strip()
    if c in svcs:
        svcs[c] = not svcs[c]
        print(f"{c} → {'ON' if svcs[c] else 'OFF'}")
    else:
        print("Not found")


def run_enabled(svcs):
    for name, enabled in svcs.items():
        if enabled:
            cmd = SERVICE_CMDS.get(name)
            if not cmd:
                print(f"No command for {name}, skipping")
                continue
            print(f"Running {name} with: {' '.join(cmd)}")
            try:
                subprocess.run(cmd, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Failed: {name}, error: {e}")


def main():
    svcs = load()
    while True:
        print("\n1.Show  2.Toggle  3.Add  4.Remove  5.Run enabled  6.Exit")
        c = input("Select: ").strip()
        if c == "1":
            show(svcs)
        elif c == "2":
            toggle(svcs)
            save(svcs)
        elif c == "3":
            n = input("New service name: ").strip()
            if n in svcs:
                print("Exists")
            else:
                svcs[n] = input("Enable? y/n: ").strip().lower() == "y"
                save(svcs)
        elif c == "4":
            n = input("Service name to remove: ").strip()
            if n in svcs:
                del svcs[n]
                save(svcs)
            else:
                print("Not found")
        elif c == "5":
            run_enabled(svcs)
        elif c == "6":
            save(svcs)
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
