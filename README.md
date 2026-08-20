# defmi

Delivery versus payment for committed holdings: two legs that move together or not at all.

## What it does

```mermaid
flowchart TB
    subgraph hidden["what settlement never reads"]
        AMT["the amounts"]
        INST["which instrument"]
        WHO["who paid whom"]
    end

    subgraph how["what hides it"]
        COM["Pedersen commitments<br/>plus a range proof"]
        TAG["a blinded asset tag<br/>fresh at every transfer"]
        NOTE["a note ledger<br/>with a one-of-many ring"]
    end

    subgraph checked["what settlement does check"]
        CONS["value is neither<br/>created nor destroyed"]
        NEG["no balance<br/>goes negative"]
        BOTH["both legs move,<br/>or neither does"]
        ONCE["one instruction<br/>settles once"]
    end

    AMT --> COM --> CONS
    INST --> TAG --> NEG
    WHO --> NOTE --> BOTH
    COM --> ONCE

    classDef secret fill:#F3E4E3,stroke:#B08C89,color:#3A2A29
    classDef mech fill:#EDEDF5,stroke:#9494B0,color:#2A2A38
    classDef ok fill:#E8EFE6,stroke:#8FA88A,color:#243024
    class AMT,INST,WHO secret
    class COM,TAG,NOTE mech
    class CONS,NEG,BOTH,ONCE ok
```

## What it is made of

```mermaid
flowchart LR
    subgraph one["one ledger: delivery versus payment"]
        SEC["securities rail"]
        CASH["cash rail"]
        SEC --- DVP{"settle"}
        CASH --- DVP
    end

    subgraph two["two ledgers: payment versus payment"]
        LA["ledger A<br/>escrow, deadline"]
        LB["ledger B<br/>escrow, deadline"]
        LA -. "an adaptor signature,<br/>never a shared value" .- LB
    end

    subgraph over["what sits over both"]
        NET["netting<br/>gross-gross to net-net"]
        CRED["credit limits<br/>that hide the sign"]
        WF["default waterfall"]
    end

    DVP --> NET
    LA --> NET
    NET --> CRED --> WF
```

Exported from a single research tree by `scripts/export_repos.py`, which is why
the layout is regular across the three repositories and why nothing here is
hand-maintained. Corrections are welcome; they belong upstream, and the export
is re-run.

## What is here

Rust:

- `rust/qomm-defmi`

Python:

- `defmi/`

`artifacts/` holds the measurements the numbers in the paper are taken from, as
the runners wrote them. Each carries the host it ran on as a label (`host-a`,
`host-b`, `host-c`); `scripts/hosts.py` is the mapping.

## Depends on

- [zkpi](https://github.com/shukob/zkpi)

Cargo picks these up as git dependencies and needs nothing from you. Python does not, so install them first:

```
pip install "zkpi @ git+https://github.com/shukob/zkpi"
```

## Running it

```
cargo test --release          # in rust/
pip install "zkpi @ git+https://github.com/shukob/zkpi"
python3 -m pytest tests/      # from the repository root
```

## Measurements

Every reported number has an artifact and a command that produces it. Where a
measurement needs something not shipped here --- MP-SPDZ, a second host, a market
data feed --- the command says so and fails rather than substituting a default.

## License

MIT. See `LICENSE`.
