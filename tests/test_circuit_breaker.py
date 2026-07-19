import pytest
import time
from src.circuit_breaker import CircuitBreaker, CircuitState

def dummy_success():
    return "success"

def dummy_failure():
    raise ValueError("forced failure")

def dummy_fallback():
    return "fallback"

def test_circuit_breaker_success():
    cb = CircuitBreaker("TestSuccess", failure_threshold=3)
    res = cb.call(dummy_success, dummy_fallback)
    assert res == "success"
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0

def test_circuit_breaker_open_fallback():
    cb = CircuitBreaker("TestOpen", failure_threshold=3, recovery_timeout=0.1)
    
    # 3 failures should open it
    for _ in range(3):
        res = cb.call(dummy_failure, dummy_fallback)
        assert res == "fallback"
        
    assert cb.state == CircuitState.OPEN
    assert cb.failure_count == 3
    
    # Next call should be fallback immediately without calling the function
    # We can test this by passing a function that would raise an error we wouldn't catch
    def explosive():
        raise RuntimeError("Should not be called")
        
    res = cb.call(explosive, dummy_fallback)
    assert res == "fallback"
    assert cb.state == CircuitState.OPEN

def test_circuit_breaker_half_open_recovery():
    cb = CircuitBreaker("TestRecovery", failure_threshold=3, recovery_timeout=0.1)
    
    # Open the circuit
    for _ in range(3):
        cb.call(dummy_failure, dummy_fallback)
        
    assert cb.state == CircuitState.OPEN
    
    # Wait for recovery timeout
    time.sleep(0.15)
    
    # First call after timeout should be HALF_OPEN and attempt the actual function
    res = cb.call(dummy_success, dummy_fallback)
    assert res == "success"
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0

def test_circuit_breaker_half_open_failure():
    cb = CircuitBreaker("TestRecoveryFail", failure_threshold=3, recovery_timeout=0.1)
    
    # Open the circuit
    for _ in range(3):
        cb.call(dummy_failure, dummy_fallback)
        
    assert cb.state == CircuitState.OPEN
    
    # Wait for recovery timeout
    time.sleep(0.15)
    
    # Call fails again in HALF_OPEN state
    res = cb.call(dummy_failure, dummy_fallback)
    assert res == "fallback"
    assert cb.state == CircuitState.OPEN  # Back to OPEN
    assert cb.failure_count == 4
