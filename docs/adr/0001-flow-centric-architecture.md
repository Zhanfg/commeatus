# ADR-0001: Flow-Centric Architecture

Status: Accepted

## Decision

Flow 是运行时一级对象。

Inbound、Outbound、DNS、Routing、AdBlock、Adaptive、Protocol 都是 Flow 生命周期中的能力，而不是整个 Core 的中心模型。

Policy Engine 负责根据 FlowContext 生成 ExecutionPlan。

Execution Runtime 负责执行 ExecutionPlan。

Compatibility formats must terminate at the compatibility boundary and be translated into the project's native typed representation.

## Core constraints

- compatibility is a boundary
- one state has one authoritative owner
- failures should remain local
- configuration updates must eventually support atomic commit and rollback
- direct traffic should avoid unnecessary userspace traversal when the platform supports it
