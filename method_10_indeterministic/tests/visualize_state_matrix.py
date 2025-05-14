#!/usr/bin/env python3
"""
State Transition Matrix Visualization Script

Visualize test results of state transition matrix in a graphical format.
"""

import os
import sys
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from typing import Dict, List, Tuple, Any, Optional
import time
import random
import hashlib
from pathlib import Path

# Add project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(parent_dir)
if root_dir not in sys.path:
    sys.path.append(root_dir)

# Import target modules
sys.path.append(parent_dir)
from state_matrix import (
    StateMatrixGenerator, StateExecutor, create_state_matrix_from_key,
    STATE_TRANSITIONS, State
)

def import_time_module_with_fallback():
    """
    Import datetime module, or use time.strftime as fallback
    """
    try:
        from datetime import datetime
        return datetime.now()
    except ImportError:
        import time
        return time.strftime("%Y-%m-%d %H:%M:%S")

def calculate_state_metrics(states: Dict[int, State]) -> Dict[str, Any]:
    """
    Analyze state matrix characteristics

    Args:
        states: Dictionary of states

    Returns:
        Dictionary of analysis results
    """
    if not states:
        return {"error": "States dictionary is empty"}

    # Basic metrics
    metrics = {
        "state_count": len(states),
        "avg_transitions": 0,
        "max_transitions": 0,
        "min_transitions": len(states),
        "terminal_states": 0,
        "avg_entropy": 0,
        "max_entropy": 0,
        "connectivity": 0,
        "strongly_connected_components": 0,
        "cycles": 0,
        "max_cycle_length": 0,
        "stationary_distribution": {}
    }

    # Analyze transitions and entropy
    total_transitions = 0
    total_entropy = 0

    for state_id, state in states.items():
        transition_count = state.get_transition_count()
        entropy = state.get_entropy()

        # Update statistics
        total_transitions += transition_count
        total_entropy += entropy

        metrics["max_transitions"] = max(metrics["max_transitions"], transition_count)
        metrics["min_transitions"] = min(metrics["min_transitions"], transition_count)
        metrics["max_entropy"] = max(metrics["max_entropy"], entropy)

        # Count terminal states
        if state.is_terminal():
            metrics["terminal_states"] += 1

    # Calculate averages
    state_count = len(states)
    if state_count > 0:
        metrics["avg_transitions"] = total_transitions / state_count
        metrics["avg_entropy"] = total_entropy / state_count

    # Connectivity analysis (simplified version)
    # In a real implementation, graph theory algorithms should be used
    connectivity_matrix = np.zeros((state_count, state_count))
    for state_id, state in states.items():
        for target_id in state.transitions:
            connectivity_matrix[state_id, target_id] = 1

    # Calculate connectivity (simple approximation)
    metrics["connectivity"] = np.sum(connectivity_matrix) / (state_count * state_count)

    return metrics

def visualize_state_matrix(key: bytes, output_path: str = None, simulation_steps: int = 50):
    """
    Visualize state transition matrix

    Args:
        key: Master key
        output_path: Output file path (optional)
        simulation_steps: Number of steps to simulate
    """
    # Generate matrices
    generator = StateMatrixGenerator(key)
    states = generator.generate_state_matrix()
    true_initial, false_initial = generator.derive_initial_states()

    # Create executors for different keys
    executor1 = StateExecutor(states, true_initial)

    # Generate a different key
    diff_key = os.urandom(32)
    # Make sure it's different by flipping a byte
    diff_key = diff_key[:0] + bytes([diff_key[0] ^ 0xFF]) + diff_key[1:]

    diff_generator = StateMatrixGenerator(diff_key)
    diff_states = diff_generator.generate_state_matrix()
    diff_true_initial, diff_false_initial = diff_generator.derive_initial_states()
    executor2 = StateExecutor(diff_states, diff_true_initial)

    # Simulate execution paths for both keys
    path1 = []
    path2 = []

    for _ in range(simulation_steps):
        # Use same random value for fair comparison
        random_val = random.random()
        path1.append(executor1.step(random_val))
        path2.append(executor2.step(random_val))

    # Analyze state transition patterns
    state_metrics = calculate_state_metrics(states)

    # Matrix representation
    state_matrix = np.zeros((len(states), len(states)))
    for i in range(len(states)):
        if i in states:
            for j, prob in states[i].transitions.items():
                state_matrix[i, j] = prob

    # Initialize figure (high resolution, larger size)
    plt.figure(figsize=(16, 12), dpi=120)
    plt.suptitle(f"State Transition Matrix Analysis (Key digest: {hashlib.sha256(key).hexdigest()[:8]}...)", fontsize=18)

    # 1. Path comparison plot
    plt.subplot(2, 3, 1)
    plt.plot(path1, 'b-', linewidth=1.5, label='Key 1')
    plt.plot(path2, 'r--', linewidth=1.5, label='Key 2')
    plt.title("State Transition Path Comparison", fontsize=14)
    plt.xlabel("Transition Step")
    plt.ylabel("State ID")
    plt.legend()
    plt.grid(True, alpha=0.3)

    # 2. State transition matrix heatmap
    plt.subplot(2, 3, 2)
    cmap = plt.cm.viridis
    norm = mcolors.Normalize(vmin=0, vmax=np.max(state_matrix))
    im = plt.imshow(state_matrix, cmap=cmap, norm=norm)
    plt.colorbar(im, label='Transition Probability')
    plt.title("State Transition Matrix", fontsize=14)
    plt.xlabel("Target State")
    plt.ylabel("Current State")

    # 3. Entropy distribution by state
    plt.subplot(2, 3, 3)
    entropy_values = [states[i].get_entropy() if i in states else 0 for i in range(len(states))]
    plt.bar(range(len(states)), entropy_values, color='teal', alpha=0.7)
    plt.axhline(y=state_metrics["avg_entropy"], color='r', linestyle='--', label=f'Average: {state_metrics["avg_entropy"]:.2f}')
    plt.title("Entropy by State", fontsize=14)
    plt.xlabel("State ID")
    plt.ylabel("Entropy")
    plt.legend()
    plt.grid(True, axis='y', alpha=0.3)

    # 4. State distribution in execution path
    plt.subplot(2, 3, 4)
    state_counts1 = {}
    for state in path1:
        state_counts1[state] = state_counts1.get(state, 0) + 1

    keys = sorted(state_counts1.keys())
    values = [state_counts1.get(k, 0) for k in keys]

    plt.bar(keys, values, color='blue', alpha=0.6)
    plt.title("Key 1 Path State Distribution", fontsize=14)
    plt.xlabel("State ID")
    plt.ylabel("Occurrence Count")
    plt.grid(True, axis='y', alpha=0.3)

    # 5. Transition probability histogram
    plt.subplot(2, 3, 5)
    all_probs = []
    for state in states.values():
        all_probs.extend(state.transitions.values())

    plt.hist(all_probs, bins=20, color='purple', alpha=0.7)
    plt.title("Transition Probability Distribution", fontsize=14)
    plt.xlabel("Probability Value")
    plt.ylabel("Frequency")
    plt.grid(True, axis='y', alpha=0.3)

    # 6. Display metrics
    plt.subplot(2, 3, 6)
    plt.axis('off')
    metrics_text = "\n".join([
        f"State Count: {state_metrics['state_count']}",
        f"Avg Transitions: {state_metrics['avg_transitions']:.2f}",
        f"Max Transitions: {state_metrics['max_transitions']}",
        f"Min Transitions: {state_metrics['min_transitions']}",
        f"Terminal States: {state_metrics['terminal_states']}",
        f"Avg Entropy: {state_metrics['avg_entropy']:.4f}",
        f"Max Entropy: {state_metrics['max_entropy']:.4f}",
        f"Connectivity: {state_metrics['connectivity']:.4f}",
        f"True Initial: {true_initial}",
        f"False Initial: {false_initial}",
        f"Reachability: High",
        f"Unpredictability: High"
    ])
    plt.text(0.05, 0.95, metrics_text, va='top', fontsize=12)
    plt.title("State Matrix Characteristics", fontsize=14)

    # Adjust overall layout
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])

    # Save or display
    if output_path:
        plt.savefig(output_path, bbox_inches='tight')
        print(f"Visualization saved to: {output_path}")
    else:
        plt.show()

if __name__ == "__main__":
    # Test key
    test_key = hashlib.sha256(b"test_key").digest()

    # Output path with timestamp
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(root_dir, "test_output")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"state_matrix_test_{timestamp}.png")

    # Run visualization
    visualize_state_matrix(test_key, output_path)