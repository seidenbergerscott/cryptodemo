import streamlit as st
import time
import random
import hashlib
from collections import defaultdict, deque
from typing import List
import altair as alt
import pandas as pd

# Import the minimal no-build component that does client-side hashing
from my_pow import my_pow

###############################################################################
# 0. Basic WebSocket-like Notifier
###############################################################################

@st.cache_resource
def get_notifier():
    """
    Global 'notifier' that calls back into each session to force a rerun.
    Not real concurrency, but a toy local approach.
    """
    class Notifier:
        def __init__(self):
            self.callbacks = []
            self.chain_version = 0

        def register(self, cb):
            self.callbacks.append(cb)

        def notify_all(self):
            self.chain_version += 1
            for c in self.callbacks:
                try:
                    c()
                except:
                    pass

    return Notifier()

def session_callback():
    # If you're on Streamlit >= 1.14, you can do st.rerun().
    # Otherwise, replace with st.experimental_rerun().
    st.rerun()  

###############################################################################
# 1. Global Blockchain Store
###############################################################################

@st.cache_resource
def get_store():
    """
    Returns a dict with:
     - blocks: { hash -> block_dict }
     - tips: set of block_hashes considered chain tips (forks allowed)
     - balances: { miner_name -> float }
     - difficulty_bits: float (leading bits must be zero, higher=harder)
     - target_time: float (desired block time in seconds)
     - recent_times: track last ~20 block production times
    """
    return {
        "blocks": {},
        "tips": set(),
        "balances": defaultdict(float),
        "difficulty_bits": 16.0,
        "target_time": 20.0,
        "recent_times": deque(maxlen=20)
    }

def create_genesis_block():
    now = time.time()
    return {
        "hash": "GENESIS",
        "height": 0,
        "parent": None,
        "merkle_root": "GENESIS",
        "nonce": 0,
        "miner": "Satoshi(Genesis)",
        "transactions": [],
        "timestamp": now,
        "block_time": 0.0,
        "difficulty": 16.0,
    }

###############################################################################
# 2. Merkle Tree
###############################################################################

def merkle_root(transactions: List[dict]) -> str:
    """Compute a simple Merkle root from a list of transaction dicts."""
    if not transactions:
        return hashlib.sha256(b"").hexdigest()

    leaves = []
    for tx in transactions:
        raw = str(sorted(tx.items())).encode()
        leaves.append(hashlib.sha256(raw).hexdigest())

    while len(leaves) > 1:
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1])
        new_level = []
        for i in range(0, len(leaves), 2):
            combo = (leaves[i] + leaves[i+1]).encode()
            new_level.append(hashlib.sha256(combo).hexdigest())
        leaves = new_level

    return leaves[0]

###############################################################################
# 3. Add + Adjust chain
###############################################################################

def add_block_to_chain(store, block):
    """
    Insert block, keep multiple tips. 
    No automatic removal of shorter tips => user can still build on them.
    """
    h = block["hash"]
    store["blocks"][h] = block

    # If parent was a tip, remove it
    if block["parent"] in store["tips"]:
        store["tips"].remove(block["parent"])

    # Add ourselves as a tip
    store["tips"].add(h)

    # block reward
    store["balances"][block["miner"]] += 50.0

    # track block_time for difficulty adjustment
    store["recent_times"].append(block["block_time"])

    # Once we have at least 5 blocks in recent_times, adjust
    if len(store["recent_times"]) >= 5:
        adjust_difficulty(store)

def adjust_difficulty(store):
    """
    If average block time < target => difficulty should go up
    else difficulty should go down.

    We do new_bits = old_bits * (target_time / avg_block_time).
    """
    if len(store["recent_times"]) == 0:
        return
    avg_bt = sum(store["recent_times"]) / len(store["recent_times"])
    old_bits = store["difficulty_bits"]

    ratio = store["target_time"] / avg_bt
    new_bits = old_bits * ratio
    new_bits = max(1.0, min(256.0, new_bits))
    store["difficulty_bits"] = new_bits

###############################################################################
# 4. Longest-Chain Helper
###############################################################################

def get_best_tip(store):
    if not store["tips"]:
        return None
    best = None
    best_h = -1
    for t in store["tips"]:
        b = store["blocks"][t]
        if b["height"] > best_h:
            best_h = b["height"]
            best = t
    return best

def walk_back_to_genesis(store, tip_hash):
    chain = []
    c = tip_hash
    while True:
        chain.append(c)
        if c == "GENESIS":
            break
        b = store["blocks"].get(c)
        if not b or not b["parent"]:
            break
        c = b["parent"]
    return chain

###############################################################################
# 5. Reset Mining State
###############################################################################

def reset_mining_state():
    for key in ["mining_active", "chunks_done", "max_chunks", "current_nonce", 
                "start_time", "chunk_keys"]:
        if key in st.session_state:
            del st.session_state[key]

###############################################################################
# 6. MAIN TAB (Client-Side PoW)
###############################################################################

def main_tab():
    st.header("Mining & Chain (Client-Side PoW)")

    store = get_store()
    notifier = get_notifier()
    notifier.register(session_callback)

    # Initialize chain with genesis if empty
    if not store["blocks"]:
        g = create_genesis_block()
        store["blocks"]["GENESIS"] = g
        store["tips"].add("GENESIS")

    st.write(f"**Difficulty**: {store['difficulty_bits']:.2f} bits (target={store['target_time']}s)")
    if "miner_name" not in st.session_state:
        st.session_state["miner_name"] = f"Miner_{random.randint(1000,9999)}"
    st.session_state["miner_name"] = st.text_input("Miner Name", st.session_state["miner_name"])
    my_bal = store["balances"][st.session_state["miner_name"]]
    st.write(f"Your balance: **{my_bal:.2f}** coins")

    # Sort all blocks by height, then time
    all_blocks_info = []
    for hsh, blk in store["blocks"].items():
        all_blocks_info.append((hsh, blk["height"], blk["timestamp"]))
    all_blocks_info.sort(key=lambda x: (x[1], x[2]))

    block_labels = []
    for (hsh, ht, ts) in all_blocks_info:
        b = store["blocks"][hsh]
        block_labels.append(f"{hsh[:8]}..(h={ht}, miner={b['miner']})")

    # Default chosen parent is best tip
    if "chosen_block_idx" not in st.session_state:
        best_tip = get_best_tip(store)
        idx = 0
        for i, (h, ht, ts) in enumerate(all_blocks_info):
            if h == best_tip:
                idx = i
                break
        st.session_state["chosen_block_idx"] = idx

    chosen_idx = st.selectbox(
        "Choose block to mine on",
        range(len(all_blocks_info)),
        format_func=lambda i: block_labels[i],
        index=st.session_state["chosen_block_idx"]
    )
    if chosen_idx != st.session_state["chosen_block_idx"]:
        st.session_state["chosen_block_idx"] = chosen_idx
        reset_mining_state()

    chosen_hash = all_blocks_info[chosen_idx][0]
    chosen_blk = store["blocks"][chosen_hash]
    next_height = chosen_blk["height"] + 1

    # Transactions for next block
    if "new_txs" not in st.session_state:
        st.session_state["new_txs"] = []
    with st.expander("Add Transactions"):
        f_ = st.text_input("From")
        t_ = st.text_input("To")
        amt_ = st.number_input("Amount", 0.0, 9999.0, step=1.0)
        if st.button("Add TX"):
            st.session_state["new_txs"].append({
                "from": f_,
                "to": t_,
                "amount": amt_,
                "txid": f"tx_{random.randint(1,9999999)}"
            })

    if st.session_state["new_txs"]:
        st.write("**Transactions for next block**:")
        for tx in st.session_state["new_txs"]:
            st.write(tx)
    else:
        st.write("_No transactions_")

    if st.button("Clear TXs"):
        st.session_state["new_txs"].clear()

    # Mining controls
    chunk_size = st.number_input("Hashes per chunk", min_value=1, value=500)
    max_chunks = st.number_input("Max chunks to try before giving up", min_value=1, value=20)
    if st.button("Reset Mining State"):
        reset_mining_state()
        st.info("Reset local mining state.")

    progress_bar = st.progress(0)
    status_area = st.empty()

    # Display current tips (possible forks)
    st.subheader("Current Tips")
    for tip_hash in store["tips"]:
        tb = store["blocks"][tip_hash]
        st.write(f"- {tip_hash[:8]}.. (h={tb['height']}, miner={tb['miner']})")

    # Initialize session state for mining
    if "mining_active" not in st.session_state:
        st.session_state["mining_active"] = False
    if "chunks_done" not in st.session_state:
        st.session_state["chunks_done"] = 0

    col1, col2 = st.columns(2)
    with col1:
        if not st.session_state["mining_active"]:
            if st.button("Start Mining"):
                st.session_state["mining_active"] = True
                st.session_state["chunks_done"] = 0
                st.session_state["current_nonce"] = 0
                st.session_state["start_time"] = time.time()
                st.session_state["max_chunks"] = max_chunks
                st.rerun()
        else:
            st.write("**Mining in progress**...")

    with col2:
        if st.session_state["mining_active"]:
            if st.button("Stop Mining"):
                st.session_state["mining_active"] = False
                st.stop()

    # If we are mining, do one chunk:
    if st.session_state["mining_active"]:
        difficulty = store["difficulty_bits"]
        mr = merkle_root(st.session_state["new_txs"])
        parent_hash = chosen_hash
        height = next_height
        current_nonce = st.session_state["current_nonce"]

        # A unique key each chunk => force re-render
        if "chunk_keys" not in st.session_state:
            st.session_state["chunk_keys"] = {}
        iteration_key = f"pow_chunk_{st.session_state['chunks_done']}"
        st.session_state["chunk_keys"][st.session_state['chunks_done']] = iteration_key

        # Make the call to the front-end
        result = my_pow(
            difficulty_bits=difficulty,
            chunk_size=chunk_size,
            parent_hash=parent_hash,
            height=height,
            merkle_root=mr,
            current_nonce=current_nonce,
            key=iteration_key
        )

        if result is None:
            # No result => front-end hasn't computed yet. Wait for next rerun
            status_area.info("No result yet... waiting for next rerun.")
            st.stop()

        found = result.get("found", False)
        new_nonce = result.get("nonce", current_nonce)
        st.session_state["current_nonce"] = new_nonce

        # For logging: how many tries in this chunk
        # If found, we effectively tried (new_nonce - old_nonce + 1).
        # If not found, we tried (new_nonce - old_nonce).
        tries_this_chunk = (new_nonce - current_nonce) + (1 if found else 0)

        status_area.write(f"**Chunk #{st.session_state['chunks_done']+1}**: Tried {tries_this_chunk} hashes.")

        if found:
            # We have a new block!
            block_time = time.time() - st.session_state["start_time"]
            block_hash = result.get("hash", None)
            st.success(f"Block found at height={height}, hash={block_hash[:8]}..")

            new_block = {
                "hash": block_hash,
                "height": height,
                "parent": parent_hash,
                "merkle_root": mr,
                "nonce": new_nonce,
                "miner": st.session_state["miner_name"],
                "transactions": st.session_state["new_txs"],
                "timestamp": time.time(),
                "block_time": block_time,
                "difficulty": difficulty,
            }
            add_block_to_chain(store, new_block)
            st.session_state["new_txs"].clear()
            reset_mining_state()

            # Notify chain watchers
            notifier.notify_all()
            st.stop()
        else:
            # Not found in this chunk => try next chunk if we haven't hit max
            st.session_state["chunks_done"] += 1
            pct = int((st.session_state["chunks_done"] / st.session_state["max_chunks"]) * 100)
            progress_bar.progress(min(pct, 100))

            if st.session_state["chunks_done"] < st.session_state["max_chunks"]:
                st.rerun()
            else:
                st.warning("No block found after max chunks. Stopping.")
                st.session_state["mining_active"] = False

    # Show all blocks
    st.subheader("All Blocks (Possible Forks)")
    by_height = {}
    for hsh, blk in store["blocks"].items():
        by_height.setdefault(blk["height"], []).append(blk)
    for hgt in sorted(by_height.keys()):
        st.markdown(f"**Height {hgt}**:")
        for b in by_height[hgt]:
            sid = b["hash"][:8]
            with st.expander(f"Block {sid}, miner={b['miner']}", expanded=False):
                st.json(b)

###############################################################################
# 7. Transaction Explorer
###############################################################################

def transaction_explorer_tab():
    st.header("Transaction Explorer (Longest Chain)")
    store = get_store()
    tip = get_best_tip(store)
    if not tip:
        st.write("No chain yet.")
        return
    chain = walk_back_to_genesis(store, tip)
    chain.reverse()
    all_txs = []
    for hsh in chain:
        if hsh == "GENESIS":
            continue
        blk = store["blocks"][hsh]
        for tx in blk["transactions"]:
            all_txs.append({
                "block_height": blk["height"],
                "miner": blk["miner"],
                "txid": tx["txid"],
                "from": tx["from"],
                "to": tx["to"],
                "amount": tx["amount"]
            })
    if all_txs:
        df = pd.DataFrame(all_txs)
        st.write("**Transactions in best chain**:")
        st.dataframe(df)
        grouped = df.groupby("block_height").size().reset_index(name="tx_count")
        c = alt.Chart(grouped).mark_bar().encode(
            x=alt.X("block_height:O", title="Block Height"),
            y=alt.Y("tx_count:Q", title="Tx Count"),
            tooltip=["tx_count"]
        )
        st.altair_chart(c, use_container_width=True)
    else:
        st.write("No transactions found in best chain.")

###############################################################################
# 8. Stats Tab
###############################################################################

def stats_tab():
    st.header("Block Time & Stats")
    store = get_store()
    blocks = list(store["blocks"].values())
    blocks.sort(key=lambda b: (b["height"], b["timestamp"]))

    data_rows = []
    for b in blocks:
        data_rows.append({
            "hash": b["hash"][:8],
            "height": b["height"],
            "miner": b["miner"],
            "time": b["timestamp"],
            "block_time": b["block_time"],
            "difficulty": f"{b['difficulty']:.2f}"
        })

    df = pd.DataFrame(data_rows)
    st.dataframe(df)
    if len(df) > 1:
        c = alt.Chart(df).mark_line(point=True).encode(
            x=alt.X("height:O", title="Block Height"),
            y=alt.Y("block_time:Q", title="Block Time(s)"),
            tooltip=["hash", "miner", "block_time", "difficulty"]
        )
        st.altair_chart(c, use_container_width=True)

###############################################################################
# 9. Main
###############################################################################

def main():
    st.title("Proof-of-Work Demo (Client-Side Chunked)")

    # Initialize store with genesis if none
    store = get_store()
    if not store["blocks"]:
        g = create_genesis_block()
        store["blocks"]["GENESIS"] = g
        store["tips"].add("GENESIS")

    tabs = st.tabs(["Mining & Chain", "Transaction Explorer", "Block Stats"])
    with tabs[0]:
        main_tab()
    with tabs[1]:
        transaction_explorer_tab()
    with tabs[2]:
        stats_tab()

if __name__ == "__main__":
    main()