# Robotics (C++/ZeroMQ/ROS2/MQTT), Energy BESS SCADA (OneATS) & Industrial OT (ISA-95 / ETCS) (`robotics-cpp-ros2-ot-scada-bess`)

> **Group:** IV. IoT, Automotive, Robotics & OT
> **Product Archetypes:** CyberPhysical_OT_Robotics, AI_Model_Serving_Engine
> **Trigger Signals:** zeromq, zmq, ros2, dds, ethercat, modbus, opcua, iec61850, scada, bess, ems, bms, plc, rtu, isa95, etcs, ato, robot, agv, amr

## [ BLOCK: unauthenticated-robot-and-ipc-command-bridges ]
### Unauthenticated HTTP/ZeroMQ/MQTT-to-Robot Actuation Bridges & Bounds Checks
- Hunt for unauthenticated network bridges (e.g., HTTP `/api/sample/call-command/` forwarding directly to EMQX `:8883`, or ZeroMQ `tcp://*:5555` `PredictRequest` servers without CURVE auth).
- Verify protobuf/message field-level bounds validation (image dimensions, view counts, joint velocity/torque limits) beyond simple total byte-size caps.

## [ BLOCK: ot-scada-bess-and-ai-in-control-loop ]
### OT SCADA/BESS (IEC 62443), 3-Party Trust Boundaries & AI-in-the-Control-Loop
- When AI forecasting models feed into OT/SCADA control loops (e.g., BESS 50MW/100MWh charge/discharge scheduling, BF-BOF furnace gas valves, or ATO rail signaling), verify whether a deterministic, hardware/PLC-enforced safety interlock independently clamps out-of-range commands regardless of AI output.
- Map 3-party trust boundaries (`Asset Owner <-> Grid/Plant Operator <-> Control Software Vendor`) and flag any remote maintenance/telemetry channel lacking dual-path isolation or safety-owner sign-off.
