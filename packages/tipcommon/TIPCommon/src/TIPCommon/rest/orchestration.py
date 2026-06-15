# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Orchestration client for managing and executing manual actions and playbook tasks."""

from __future__ import annotations

import contextlib
import json
import logging
from typing import Any

from TIPCommon.base.action import ExecutionState
from TIPCommon.base.data_models import ActionJsonOutput, ActionOutput
from TIPCommon.rest.soar_api import (
    execute_manual_action,
    get_action_result_by_id,
    get_env_action_def_files,
    get_installed_integrations_of_environment,
)

logger = logging.getLogger(__name__)


def _build_action_output(response_json: dict[str, Any]) -> ActionOutput:
    status = response_json.get("Status") if response_json.get("Status") is not None else response_json.get("status")
    if status in {1, 5, 13, "AsyncPending", "Started", "PendingRetry", "In Progress"}:
        exec_state = ExecutionState.IN_PROGRESS
    elif status in {2, 7, "Completed", "HandledTimedout"}:
        exec_state = ExecutionState.COMPLETED
    else:
        exec_state = ExecutionState.FAILED

    result_json_str = (
        response_json.get("ResultJsonObject")
        if response_json.get("ResultJsonObject") is not None
        else response_json.get("resultJsonObject")
    )
    json_output = None
    if result_json_str:
        with contextlib.suppress(Exception):
            json_result_dict = json.loads(result_json_str)
            json_output = ActionJsonOutput(
                title="JsonResult", content="", is_for_entity=False, json_result=json_result_dict
            )

    action_output = ActionOutput(
        output_message=response_json.get("Message")
        if response_json.get("Message") is not None
        else (response_json.get("message") or ""),
        result_value=response_json.get("ResultValue")
        if response_json.get("ResultValue") is not None
        else (response_json.get("resultValue") or ""),
        execution_state=exec_state,
        json_output=json_output,
        debug_output="",
    )
    # Dynamically attach raw response and id for polling/backward-compatibility
    action_output.raw = response_json
    action_output.id = response_json.get("Id") if response_json.get("Id") is not None else response_json.get("id")
    action_output.status = status
    return action_output


def get_action_result(siemplify: Any, result_id: str) -> ActionOutput:
    """Gets the action execution result by its ID.

    Args:
        siemplify: ChronicleSOAR/SiemplifyAction object.
        result_id (str): The ID of the action result.

    Returns:
        ActionOutput: Action execution output object.
    """
    response = get_action_result_by_id(chronicle_soar=siemplify, result_id=result_id)
    return _build_action_output(response.json())


def _resolve_integration_instance(siemplify: Any, integration_identifier: str, instance: str) -> str:
    """Resolves the correct integration instance identifier based on the provided strategy."""
    if instance == "auto":
        # Determine environment to query
        env = getattr(siemplify.current_alert, "environment", None) or siemplify.environment
        instances = get_installed_integrations_of_environment(siemplify, env, integration_identifier)
        if not instances:
            # Fall back to shared
            instances = get_installed_integrations_of_environment(siemplify, "Shared Instances", integration_identifier)

        if not instances:
            raise RuntimeError(f"Could not find any installed instance for integration '{integration_identifier}'")
        return instances[0].identifier
    elif instance == "shared":
        instances = get_installed_integrations_of_environment(siemplify, "Shared Instances", integration_identifier)
        if not instances:
            raise RuntimeError(f"Could not find any installed instance for integration '{integration_identifier}'")
        return instances[0].identifier

    # Explicit instance identifier provided
    return instance


def _build_entity_payload(siemplify: Any, case_id: str, ent: Any) -> dict[str, Any]:
    """Constructs the entity payload dictionary from a given entity object."""
    return {
        "caseId": case_id,
        "identifier": ent.identifier,
        "entityType": ent.entity_type,
        "isInternal": ent.is_internal,
        "isSuspicious": ent.is_suspicious,
        "isArtifact": ent.is_artifact,
        "isEnriched": getattr(ent, "is_enriched", False),
        "isVulnerable": getattr(ent, "is_vulnerable", False),
        "isPivot": getattr(ent, "is_pivot", False),
        "environment": getattr(ent, "environment", None)
        or getattr(siemplify.current_alert, "environment", None)
        or siemplify.environment,
    }


def _validate_and_populate_action_parameters(
    siemplify: Any, integration_identifier: str, full_action_name: str, action_parameters: dict[str, Any]
) -> dict[str, Any]:
    """Validates required action parameters and populates missing ones with default values."""
    action_params_copy = action_parameters.copy()
    try:
        action_defs = get_env_action_def_files(siemplify)
        matching_action_def = None

        if isinstance(action_defs, list):
            for action_def in action_defs:
                if (
                    isinstance(action_def, dict)
                    and action_def.get("IntegrationIdentifier") == integration_identifier
                    and action_def.get("Name") == full_action_name
                ):
                    matching_action_def = action_def
                    break

        if matching_action_def:
            for param in matching_action_def.get("Parameters", []):
                param_name = param.get("Name")
                default_val = param.get("DefaultValue")
                is_mandatory = param.get("IsMandatory", False)

                if param_name:
                    if param_name not in action_params_copy:
                        # If mandatory and no default value is defined, raise exception
                        if is_mandatory and (default_val is None or default_val == ""):
                            raise ValueError(
                                f"Mandatory parameter '{param_name}' is missing for action '{full_action_name}'."
                            )

                        # Populate with default value if it exists, otherwise empty string
                        if default_val is not None:
                            action_params_copy[param_name] = default_val
                        else:
                            action_params_copy[param_name] = ""
                    else:
                        # Param is present, check if it's empty and mandatory
                        param_value = action_params_copy[param_name]
                        if is_mandatory and (param_value is None or param_value == ""):
                            raise ValueError(
                                f"Mandatory parameter '{param_name}' has an empty value for action '{full_action_name}'."
                            )
    except ValueError as ve:
        # Mandatory parameter missing should propagate as an error
        logger.error(str(ve))
        raise
    except Exception as e:
        logger.warning(
            f"Failed to fetch action definitions to populate default parameters: {e}. "
            f"Proceeding with provided action parameters."
        )
    return action_params_copy


def execute_orchestrated_action(
    siemplify: Any,
    integration_identifier: str,
    action_name: str,
    *,
    instance: str = "auto",
    action_parameters: dict[str, Any] | None = None,
    entity_scope: str = "inherit",
    entity_identifiers: str | None = None,
    action_provider: str = "Scripts",
) -> ActionOutput:
    """Resolves correct integration instance and triggers the manual action.

    Args:
        siemplify: ChronicleSOAR/SiemplifyAction object.
        integration_identifier (str): Identifier of the integration (e.g. 'GoogleThreatIntelligence').
        action_name (str): Name of the action to execute (e.g. 'Ping').
        instance (str): Instance selection mode ('auto', 'shared' or explicit instance name). Defaults to 'auto'.
        action_parameters (dict[str, Any] | None): Dictionary of action parameters. Defaults to empty dict.
        entity_scope (str): Scope of entities ('inherit', 'custom' or predefined scope like 'All entities'). Defaults to 'inherit'.
        entity_identifiers (str | None): CSV list of entity identifiers to use if entity_scope is 'custom'. Defaults to None.
        action_provider (str): Action provider name. Defaults to 'Scripts'.

    Returns:
        ActionOutput: Action execution output object.
    """
    if action_parameters is None:
        action_parameters = {}
    # 1. Resolve integration instance
    instance_id = _resolve_integration_instance(siemplify, integration_identifier, instance)

    # 2. Extract Alert / Case details
    case_id = siemplify.case_id
    alert_group_identifier = siemplify.current_alert.alert_group_identifier

    # 3. Handle entities
    payload_entities = []
    scope = ""
    is_predefined_scope = False

    if entity_scope == "inherit":
        scope = ""
        is_predefined_scope = False
        for ent in siemplify.current_alert.entities:
            payload_entities.append(_build_entity_payload(siemplify, case_id, ent))
    elif entity_scope == "custom":
        scope = ""
        is_predefined_scope = False
        if not entity_identifiers:
            raise ValueError("entity_identifiers must be provided when entity_scope is 'custom'")

        identifiers = [e.strip() for e in entity_identifiers.split(",")]
        alert_entities_map = {ent.identifier: ent for ent in siemplify.current_alert.entities}

        for identifier in identifiers:
            if identifier not in alert_entities_map:
                raise ValueError(f"entity not found in the scope of the alert: {identifier}")
            ent = alert_entities_map[identifier]
            payload_entities.append(_build_entity_payload(siemplify, case_id, ent))
    else:
        # Predefined scope like "All entities", "Internal entities", etc.
        scope = entity_scope
        is_predefined_scope = True
        payload_entities = []

    full_action_name = f"{integration_identifier}_{action_name}"

    # Fetch action definitions and populate default parameter values if missing
    action_parameters = _validate_and_populate_action_parameters(
        siemplify, integration_identifier, full_action_name, action_parameters
    )

    action_properties = {
        "ScriptName": full_action_name,
        "ScriptParametersEntityFields": json.dumps({k: str(v) for k, v in action_parameters.items()}),
        "IntegrationInstance": instance_id,
    }

    # 4. Trigger manual action
    try:
        response = execute_manual_action(
            chronicle_soar=siemplify,
            case_id=case_id,
            action_name=full_action_name,
            action_properties=action_properties,
            alert_group_identifiers=[alert_group_identifier],
            scope=scope,
            target_entities=payload_entities,
            is_predefined_scope=is_predefined_scope,
            action_provider=action_provider,
        )
        response_json = response.json()
        logger.info(f"Manual action triggered successfully. Response details: {json.dumps(response_json)}")
        return _build_action_output(response_json)
    except Exception as e:
        error_details = {
            "error_message": str(e),
            "case_id": case_id,
            "action_name": full_action_name,
            "action_properties": action_properties,
            "alert_group_identifiers": [alert_group_identifier],
            "scope": scope,
            "is_predefined_scope": is_predefined_scope,
            "payload_entities": payload_entities,
            "action_provider": action_provider,
        }
        if hasattr(e, "response") and e.response is not None:
            error_details["response_status_code"] = getattr(e.response, "status_code", None)
            with contextlib.suppress(Exception):
                error_details["response_text"] = e.response.text

        logger.info(f"Execution call failed. API response/error details: {json.dumps(error_details)}")
        raise
