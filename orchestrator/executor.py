"""Master Orchestrator executor

Main entry point for composite agent coordination.
Routes requests by intent to appropriate agents and aggregates responses.
"""

import os
from typing import Any, Dict, Optional, List
from uuid import uuid4
import time

from agents.shared.logger import AgentLogger
from agents.shared.response_builder import ResponseBuilder
from agents.shared.schema_validator import SchemaValidator
from agents.systems import SystemsAgent
from agents.offensive import OffensiveAgent
from agents.defensive import DefensiveAgent

from .router import RequestRouter
from .aggregator import ResponseAggregator
from .constants import INTENT_TO_AGENT, MIXED_INTENT_SEQUENCE
from .errors import ValidationError, RoutingError, AggregationError, AgentExecutionError, OrchestratorTimeoutError

# Wall-clock deadline for the entire orchestration pipeline (seconds).
# Override via the KGCS_ORCHESTRATOR_TIMEOUT environment variable.
_ORCHESTRATOR_TIMEOUT_S = float(os.getenv("KGCS_ORCHESTRATOR_TIMEOUT", "30"))


class MasterOrchestrator:
    """Master Orchestrator for composite agent coordination.

    Routes requests by intent to appropriate microservices, aggregates responses,
    and handles mixed-intent queries.
    """

    def __init__(self, correlation_id: Optional[str] = None):
        """Initialize MasterOrchestrator.

        Args:
            correlation_id: Request correlation ID (optional; generated if not provided)
        """
        self.correlation_id = correlation_id or str(uuid4())
        self.logger = AgentLogger("orchestrator.master", self.correlation_id)
        self.response_builder = ResponseBuilder()
        self.schema_validator = SchemaValidator()
        self.router = RequestRouter()
        self.aggregator = ResponseAggregator()

        # Initialize agent instances (shared Neo4j client)
        self.systems_agent = SystemsAgent(correlation_id=self.correlation_id)
        self.offensive_agent = OffensiveAgent(correlation_id=self.correlation_id)
        self.defensive_agent = DefensiveAgent(correlation_id=self.correlation_id)

        self.agents = {
            "systems": self.systems_agent,
            "offensive": self.offensive_agent,
            "defensive": self.defensive_agent
        }

    def execute(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Execute orchestration request.

        Flow:
        1. Update correlation_id from request
        2. Extract and validate intent and payload
        3. Route to agent(s) by intent
        4. Execute agent(s)
        5. Aggregate responses (if multi-agent)
        6. Validate final response
        7. Return aggregated response

        Args:
            request: Full request envelope with version, correlation_id, agent, intent, payload

        Returns:
            Response envelope dict matching agent-consumable-schema.json

        Raises:
            OrchestratorTimeoutError: Propagated uncaught so the API layer can return 504.
        """
        try:
            # Update correlation ID
            self.correlation_id = request.get("correlation_id", self.correlation_id)
            self.logger = AgentLogger("orchestrator.master", self.correlation_id)

            self.logger.info("execute() start")
            t0 = time.perf_counter()
            deadline = t0 + _ORCHESTRATOR_TIMEOUT_S

            # Extract request fields
            intent = request.get("intent")
            payload = request.get("payload", {})

            self.logger.info(f"intent={intent}, payload_keys={list(payload.keys())}")

            # Validate intent
            try:
                self.router.validate_intent(intent)
            except ValidationError as e:
                self.logger.error(f"Invalid intent: {str(e)}")
                return self.response_builder.error(
                    errors=[str(e)],
                    correlation_id=self.correlation_id
                )

            # Validate payload
            try:
                self.router.validate_payload(intent, payload)
            except ValidationError as e:
                self.logger.error(f"Invalid payload: {str(e)}")
                return self.response_builder.error(
                    errors=[str(e)],
                    correlation_id=self.correlation_id
                )

            # Route and execute
            if intent == "mixed":
                response = self._execute_mixed_intent(request, deadline)
            else:
                response = self._execute_single_intent(intent, request, deadline)

            self.logger.info("execute() success", latency_ms=round((time.perf_counter() - t0) * 1000, 1), intent=intent)
            return response

        except OrchestratorTimeoutError:
            raise

        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}", exc=e)
            return self.response_builder.error(
                errors=["Internal orchestrator error"],
                correlation_id=self.correlation_id
            )

    def _execute_single_intent(self, intent: str, request: Dict[str, Any], deadline: float) -> Dict[str, Any]:
        """Execute single-intent request (route to one agent).

        Args:
            intent: Request intent (vuln_lookup, attack_path, or coverage_map)
            request: Full request envelope
            deadline: Absolute wall-clock deadline (time.perf_counter() value)

        Returns:
            Agent response (pass-through, no aggregation)

        Raises:
            OrchestratorTimeoutError: Propagated uncaught to the caller.
        """
        try:
            # Route to agent
            agent_name = self.router.route_intent(intent)
            agent = self.agents.get(agent_name)

            if not agent:
                raise RoutingError(f"Agent not found: {agent_name}")

            # Deadline check before dispatching — prevents starting a new agent
            # when the pipeline has already exceeded its budget.
            if time.perf_counter() >= deadline:
                raise OrchestratorTimeoutError(
                    f"Pipeline deadline exceeded before dispatching {agent_name}"
                )

            self.logger.info(f"Routing to {agent_name} agent for intent={intent}")

            # Execute agent with timing
            try:
                t_agent = time.perf_counter()
                response = agent.execute(request)
                agent_ms = round((time.perf_counter() - t_agent) * 1000, 1)
            except TimeoutError as exc:
                raise OrchestratorTimeoutError(
                    f"Agent {agent_name} timed out: {exc}"
                ) from exc

            # Validate response
            self.schema_validator.validate_response(agent_name, response)
            self.logger.info(f"Response validation passed for {agent_name}", latency_ms=agent_ms, intent=intent)

            return response

        except RoutingError as e:
            self.logger.error(f"Routing error: {str(e)}")
            return self.response_builder.error(
                errors=[str(e)],
                correlation_id=self.correlation_id
            )

        except OrchestratorTimeoutError:
            raise

        except Exception as e:
            self.logger.error(f"Agent execution error: {str(e)}", exc=e)
            return self.response_builder.error(
                errors=["Agent execution failed"],
                correlation_id=self.correlation_id
            )

    def _execute_mixed_intent(self, request: Dict[str, Any], deadline: float) -> Dict[str, Any]:
        """Execute mixed-intent request (route to multiple agents in sequence).

        Sequence (for CPE/CVE input):
        1. Systems Agent: vuln_lookup → get vulnerabilities
        2. Offensive Agent: attack_path → get attack paths using CVE from Systems
        3. Defensive Agent: coverage_map → get defensive coverage using technique from Offensive

        Args:
            request: Full request envelope
            deadline: Absolute wall-clock deadline (time.perf_counter() value)

        Returns:
            Aggregated response from all agents

        Raises:
            OrchestratorTimeoutError: Propagated uncaught to the caller.
        """
        try:
            self.logger.info("Executing mixed-intent sequence")

            responses = []
            payload_context = dict(request.get("payload", {}))

            # Execute agents in sequence
            for agent_name, sub_intent in MIXED_INTENT_SEQUENCE:
                agent = self.agents.get(agent_name)

                if not agent:
                    raise RoutingError(f"Agent not found: {agent_name}")

                # Deadline check before each step
                if time.perf_counter() >= deadline:
                    raise OrchestratorTimeoutError(
                        f"Pipeline deadline exceeded before mixed step {agent_name}/{sub_intent}"
                    )

                self.logger.info(f"Executing {agent_name} agent (intent={sub_intent})")

                step_payload = self._build_mixed_payload(sub_intent, payload_context, responses)
                if not step_payload:
                    error_response = self.response_builder.error(
                        errors=[f"Unable to derive payload for mixed step: {sub_intent}"],
                        correlation_id=self.correlation_id
                    )
                    responses.append(error_response)
                    self.logger.warning(f"Stopping mixed sequence: missing payload for {sub_intent}")
                    break

                # Create request for this agent
                agent_request = dict(request)
                agent_request["intent"] = sub_intent
                agent_request["agent"] = agent_name
                agent_request["payload"] = step_payload

                # Execute agent with timing
                try:
                    t_agent = time.perf_counter()
                    response = agent.execute(agent_request)
                    agent_ms = round((time.perf_counter() - t_agent) * 1000, 1)
                except TimeoutError as exc:
                    raise OrchestratorTimeoutError(
                        f"Agent {agent_name} timed out during mixed step: {exc}"
                    ) from exc

                responses.append(response)

                payload_context.update(step_payload)
                payload_context.update(self._extract_mixed_context(sub_intent, response))

                self.logger.info(
                    f"{agent_name} returned status={response.get('status')}",
                    latency_ms=agent_ms,
                    intent=sub_intent,
                )

                # If agent failed, stop sequence
                if response.get("status") == "error":
                    self.logger.warning(f"Agent {agent_name} failed, stopping sequence")
                    break

            # Aggregate responses
            aggregated = self.aggregator.aggregate_multi_agent_responses(responses)

            # Validate aggregated response
            # Note: aggregated response may not match a single schema, so skip validation for now
            # In a real system, you'd validate the top-level envelope structure
            self.logger.info("Multi-agent response aggregated")

            return aggregated

        except (RoutingError, AggregationError) as e:
            self.logger.error(f"Mixed-intent execution error: {str(e)}")
            return self.response_builder.error(
                errors=[str(e)],
                correlation_id=self.correlation_id
            )

        except OrchestratorTimeoutError:
            raise

        except Exception as e:
            self.logger.error(f"Unexpected error in mixed-intent: {str(e)}", exc=e)
            return self.response_builder.error(
                errors=["Mixed-intent execution failed"],
                correlation_id=self.correlation_id
            )

    def _build_mixed_payload(
        self,
        sub_intent: str,
        payload_context: Dict[str, Any],
        prior_responses: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Build payload for each mixed-intent step using request + prior outputs."""
        if sub_intent == "vuln_lookup":
            if payload_context.get("matchCriteriaId"):
                return {"matchCriteriaId": payload_context["matchCriteriaId"]}
            if payload_context.get("cpeName"):
                return {"cpeName": payload_context["cpeName"]}
            if payload_context.get("cpe"):
                return {"cpe": payload_context["cpe"]}
            if payload_context.get("cveId"):
                return {"cveId": payload_context["cveId"]}
            return dict(payload_context)

        if sub_intent == "attack_path":
            cwe_id = payload_context.get("cweId")
            if not cwe_id and prior_responses:
                cwe_id = self._extract_cwe_id(prior_responses[-1])
            if cwe_id:
                return {"cweId": cwe_id}
            if payload_context.get("cveId"):
                return {"cveId": payload_context["cveId"]}
            return dict(payload_context)

        if sub_intent == "coverage_map":
            attack_id = payload_context.get("attackId")
            if not attack_id and prior_responses:
                attack_id = self._extract_attack_id(prior_responses[-1])
            if attack_id:
                return {"attackId": attack_id}
            return dict(payload_context)

        return {}

    @staticmethod
    def _extract_mixed_context(sub_intent: str, response: Dict[str, Any]) -> Dict[str, Any]:
        """Extract context values from a sub-agent response for downstream steps."""
        if response.get("status") != "ok":
            return {}

        if sub_intent == "vuln_lookup":
            cwe_id = MasterOrchestrator._extract_cwe_id(response)
            return {"cweId": cwe_id} if cwe_id else {}

        if sub_intent == "attack_path":
            attack_id = MasterOrchestrator._extract_attack_id(response)
            return {"attackId": attack_id} if attack_id else {}

        return {}

    @staticmethod
    def _extract_cwe_id(response: Dict[str, Any]) -> Optional[str]:
        """Extract first CWE ID from systems response payload."""
        data = response.get("data") or {}
        vulnerabilities = data.get("vulnerabilities") or []
        for vulnerability in vulnerabilities:
            weakness = vulnerability.get("weakness") or {}
            cwe_id = weakness.get("cweId")
            if cwe_id:
                return cwe_id
        return None

    @staticmethod
    def _extract_attack_id(response: Dict[str, Any]) -> Optional[str]:
        """Extract first ATT&CK technique ID from offensive response payload."""
        data = response.get("data") or {}

        techniques = data.get("techniques") or []
        for technique in techniques:
            attack_id = technique.get("id") or technique.get("attackId")
            if attack_id:
                return attack_id

        attack_paths = data.get("attack_paths") or []
        for attack_path in attack_paths:
            attack_id = attack_path.get("technique_id")
            if attack_id:
                return attack_id

        return None
