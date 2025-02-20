# Architectural Decision Record - Standalone Fuzzing Component

- [ ] ADR under construction 🚧
- [ ] In Review ⏳
- [x] Accepted ✅
- [ ] Rejected ❌

# Context and Problem Statement

"We want to run the fuzzer async and also concurrently from the patch-generation and the patch-evaluation system components, because each fuzzer run for each potentially vulnerable program can be a long running job"

## Options Considered
- A: Extract python code as is from autopatch-llm 
- B: implement fuzzing service in golang
- C: implement fuzzing service in C

## Decision Outcome

Option A Extract and refactor python code from main component into standalone python component and container

## Consequences

### Option A
- positives - python  - python code already exists and is tested as basically functional- negatives - python  - low support for concurrency

### Option B
- positives - golang
  - high support for concurrency
- negatives - golang  - mental overhead of using different programming language   - requires additional testing

### Option C
- positives - C
  - performant  - familiar to Professor Wang
- negatives - C  - mental overhead of using different programming language   - low level APIs negatively affect development velocity
