<?php

// Code Smell: Massive duplicate Logic (DRY Violation)
class ProcessorA {
    public function handle() {
        echo "Starting process...\n";
        $data = [1, 2, 3, 4, 5];
        foreach ($data as $item) {
            if ($item % 2 == 0) {
                echo "Even: " . $item . "\n";
            }
        }
        echo "Ending process...\n";
    }
}

class ProcessorB {
    public function handle() {
        // EXACT copy paste of previous logic with no abstraction
        echo "Starting process...\n";
        $data = [1, 2, 3, 4, 5];
        foreach ($data as $item) {
            if ($item % 2 == 0) {
                echo "Even: " . $item . "\n";
            }
        }
        echo "Ending process...\n";
    }
}
?>
