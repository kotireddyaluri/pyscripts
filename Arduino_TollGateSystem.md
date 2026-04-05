```C
// =============================================
// 🤖 OBSTACLE DETECTOR + SERVO PROJECT
// This project uses a sensor to measure distance.
// If something gets too close (under 20 cm),
// the servo motor turns — like a gate opening!
// =============================================

// This library lets us easily control servo motors
#include <Servo.h>

// --- PIN NUMBERS ---
// Think of pins like the holes where we plug in our wires!
const int trigPin = 7;  // TRIG = sends out a sound wave (like yelling "HELLO!")
const int echoPin = 6;  // ECHO = listens for the sound to bounce back
const int servoPin = 5; // This is where the servo motor wire is plugged in

// Create a servo "remote control" so we can tell it what to do
Servo myServo;

// =============================================
// SETUP — Runs ONE TIME when the Arduino turns on
// =============================================
void setup() {

  // Start the Serial Monitor so we can read messages on the computer
  // 9600 is the "speed" of communication (like choosing a radio channel)
  Serial.begin(9600);

  // Tell Arduino: trigPin will SEND signals (OUTPUT = talking)
  pinMode(trigPin, OUTPUT);

  // Tell Arduino: echoPin will RECEIVE signals (INPUT = listening)
  pinMode(echoPin, INPUT);

  // Connect the servo motor to pin 5
  myServo.attach(servoPin);

  // Start the servo at 0 degrees — its resting/home position
  myServo.write(0);
}

// =============================================
// LOOP — Runs AGAIN AND AGAIN forever!
// =============================================
void loop() {

  // --- STEP 1: SEND A SOUND WAVE ---
  // This is like the sensor clapping its hands to make a sound!

  // First, make sure the sensor is quiet and reset
  digitalWrite(trigPin, LOW);
  delayMicroseconds(2);   // Wait 2 microseconds (super tiny pause)

  // Send a short sound pulse — too high-pitched for humans to hear!
  digitalWrite(trigPin, HIGH);
  delayMicroseconds(10);  // Keep sending for 10 microseconds
  digitalWrite(trigPin, LOW);   // Stop sending the sound

  // --- STEP 2: LISTEN FOR THE ECHO ---
  // pulseIn() waits for the sound to bounce back and measures HOW LONG it took
  // The longer it takes, the farther away the object is!
  long duration = pulseIn(echoPin, HIGH);
  // 'duration' is measured in microseconds

  // --- STEP 3: CALCULATE THE DISTANCE ---
  // Sound travels 0.034 cm every microsecond
  // We divide by 2 because the sound goes TO the object AND back again
  // Formula: Distance = (Time × Speed of Sound) ÷ 2
  float distance = duration * 0.034 / 2;

  // --- STEP 4: PRINT THE DISTANCE TO THE COMPUTER ---
  // Open Serial Monitor (Ctrl+Shift+M) to see these messages!
  Serial.print("Distance: ");
  Serial.print(distance);     // Shows the number, e.g. 15.3
  Serial.println(" cm");      // Adds " cm" and moves to next line

  // --- STEP 5: DECIDE WHAT THE SERVO SHOULD DO ---
  if (distance < 20) {
    // 🚨 Something is CLOSE! (less than 20 cm = about the width of a book)
    myServo.write(90);  // Turn the servo to 90 degrees (like opening a door!)

  } else {
    // ✅ Nothing nearby — all clear!
    myServo.write(0);   // Return the servo back to 0 degrees (resting position)
  }

  // --- STEP 6: TAKE A SHORT BREAK ---
  // Wait 200 milliseconds before measuring again
  // That's only 1/5 of a second — fast enough to catch moving objects!
  delay(200);
}
```
