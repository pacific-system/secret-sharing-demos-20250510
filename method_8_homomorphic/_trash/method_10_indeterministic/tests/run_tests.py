#!/usr/bin/env python3
"""
Indeterministic Transcription Encryption Test Runner

Executes all tests and outputs results.
"""

import os
import sys
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Any

# Add project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
root_dir = os.path.dirname(parent_dir)
if root_dir not in sys.path:
    sys.path.append(root_dir)

# Import test modules
from method_10_indeterministic.state_matrix import (
    STATE_MATRIX_SIZE, STATE_TRANSITIONS, create_state_matrix_from_key
)

class TestResult:
    """Class to manage test results"""

    def __init__(self, name: str):
        self.name = name
        self.tests = []
        self.passed = 0
        self.failed = 0
        self.start_time = time.time()
        self.end_time = None

    def add_test(self, test_name: str, success: bool, error_message: str = None):
        """
        Add a test result

        Args:
            test_name: Name of the test
            success: True if passed, False if failed
            error_message: Error message if failed
        """
        self.tests.append({
            "name": test_name,
            "success": success,
            "error": error_message
        })

        if success:
            self.passed += 1
        else:
            self.failed += 1

    def finish(self):
        """Mark testing as complete and record end time"""
        self.end_time = time.time()

    def get_duration(self) -> float:
        """Get test duration in seconds"""
        if self.end_time is None:
            return time.time() - self.start_time
        return self.end_time - self.start_time

    def print_summary(self):
        """Print test summary to console"""
        print(f"\n{self.name} Test Results:")
        print(f"Total: {len(self.tests)} tests")
        print(f"Passed: {self.passed} tests")
        print(f"Failed: {self.failed} tests")
        print(f"Execution Time: {self.get_duration():.2f} seconds")

        if self.failed > 0:
            print("\nFailed Tests:")
            for test in self.tests:
                if not test["success"]:
                    print(f"- {test['name']}: {test['error']}")

def test_state_matrix_generation():
    """Test state matrix generation and transition"""

    result = TestResult("State Transition Matrix")

    try:
        # Test key generation
        test_key = os.urandom(32)
        result.add_test("Key Generation", True)

        # Test matrix generation
        generator_creation_start = time.time()
        states, true_initial, false_initial = create_state_matrix_from_key(test_key)
        generator_creation_time = time.time() - generator_creation_start

        result.add_test(
            "Matrix Generation",
            len(states) == STATE_MATRIX_SIZE,
            f"Expected {STATE_MATRIX_SIZE} states, got {len(states)}"
        )

        # Test initial states
        result.add_test(
            "Initial States Difference",
            true_initial != false_initial,
            "True and False initial states should be different"
        )

        # Test state transitions
        from method_10_indeterministic.state_matrix import StateExecutor

        # Regular path (true)
        true_executor = StateExecutor(states, true_initial)
        true_path = []

        # Run transitions
        for _ in range(STATE_TRANSITIONS):
            true_path.append(true_executor.step())

        result.add_test(
            "True Path Execution",
            len(true_path) == STATE_TRANSITIONS,
            f"Expected {STATE_TRANSITIONS} transitions, got {len(true_path)}"
        )

        # False path
        false_executor = StateExecutor(states, false_initial)
        false_path = []

        # Use the same random values for comparable test
        for _ in range(STATE_TRANSITIONS):
            # Generate a more robust random value that ensures different paths
            # But is deterministic for test reproducibility
            state_index = len(true_path) % STATE_MATRIX_SIZE
            salt = hashlib.sha256(f"{test_key.hex()[:8]}_{state_index}".encode()).digest()
            random_val = int.from_bytes(salt[:4], byteorder='big') / 0xFFFFFFFF

            # Run both executors with same random value
            new_true_state = true_executor.step(random_val)
            new_false_state = false_executor.step(random_val)

            true_path.append(new_true_state)
            false_path.append(new_false_state)

        # Check paths differ
        paths_differ = true_path != false_path
        result.add_test(
            "Path Difference",
            paths_differ,
            "True and False paths should differ"
        )

        # Run visualization if needed
        generate_visualization = True

        if generate_visualization and paths_differ:
            try:
                from method_10_indeterministic.tests.visualize_state_matrix import visualize_state_matrix

                # Output path with timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = os.path.join(root_dir, "test_output", f"state_matrix_test_{timestamp}.png")

                # Run visualization
                visualize_state_matrix(test_key, output_path)
                result.add_test("Visualization", True)
            except Exception as e:
                result.add_test("Visualization", False, f"Exception: {str(e)}")

        # Test execution time
        result.add_test(
            "Performance",
            generator_creation_time < 5.0,  # 5 seconds timeout
            f"Matrix generation took too long: {generator_creation_time:.2f} seconds"
        )

    except Exception as e:
        result.add_test("Unexpected Error", False, str(e))

    result.finish()
    return result

def run_all_tests():
    """Run all test suites"""

    print("=" * 60)
    print("Indeterministic Transcription Encryption Test Run")
    print(f"Run Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    results = []

    # Run state matrix tests
    state_matrix_results = test_state_matrix_generation()
    results.append(state_matrix_results)
    state_matrix_results.print_summary()

    # Overall summary
    print("\n" + "=" * 60)
    print("Overall Summary")
    print("=" * 60)

    total_tests = sum(result.passed + result.failed for result in results)
    total_passed = sum(result.passed for result in results)
    total_failed = sum(result.failed for result in results)

    if total_tests > 0:
        pass_rate = total_passed / total_tests * 100
    else:
        pass_rate = 0

    print(f"Total Tests: {total_tests}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failed}")
    print(f"Pass Rate: {pass_rate:.2f}%")

    # Final verdict
    if total_failed == 0:
        print("\nFinal Verdict: Success ✅")
        return True
    else:
        print("\nFinal Verdict: Failure ❌")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
