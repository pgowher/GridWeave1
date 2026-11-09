"""S04 physical raw backend layer.

The layer keeps electrical simulation behind backend interfaces and emits
contract-bound raw physical streams. Every currently executable backend is a
controlled procedural synthetic profile. Style profiles may reproduce selected
shape or topology ideas, but they do not import, execute, or claim conformance
with OpenSynth, Faraday, SMART-DS, SimBench, or an external power-flow solver.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import cos, pi, sin
from typing import Any, Iterable, Mapping, Protocol

from htgl_dataset_generator.config import (
    CONTROLLED_SYNTHETIC_PHYSICAL_PROFILES,
    DEFERRED_EXTERNAL_PHYSICAL_BACKENDS,
    ResolvedConfig,
    ResolvedRunPlan,
)
from htgl_dataset_generator.schemas import ContractSpec, load_contract, validate_record
from htgl_dataset_generator.seeds import CounterRng, deterministic_uuid, seed_stream_records_for_plan
from htgl_dataset_generator.world import FederatedWorld, build_federated_world


PHYSICAL_COMPONENT = "S04.physical_raw"
EPSILON = 1e-9
EXTERNAL_SOLVER_EXECUTION_SUPPORTED = False


class PhysicalValidationError(ValueError):
    """Raised when physical raw rows violate S04 invariants."""


@dataclass(frozen=True)
class NetworkTopologyElement:
    element_id: str
    scenario_id: str
    region_id: str
    network_area_id: str
    element_class: str
    parent_element_id: str | None
    nominal_voltage_v: float | None
    capacity_kw: float


@dataclass(frozen=True)
class PhysicalViolation:
    violation_id: str
    scenario_id: str
    source_table: str
    source_id: str
    violation_type: str
    severity: str
    message: str


@dataclass(frozen=True)
class GovernanceTrigger:
    trigger_id: str
    scenario_id: str
    source_table: str
    source_id: str
    trigger_type: str
    event_family: str
    region_id: str
    timestamp: str
    affected_cohort_id: str | None
    description: str


@dataclass(frozen=True)
class PhysicalDiagnostics:
    scenario_id: str
    backend_mode: str
    meter_reading_count: int
    der_telemetry_count: int
    network_state_count: int
    context_event_count: int
    trigger_count: int
    topology_element_count: int
    represented_meter_total: float
    min_meter_autocorrelation: float
    max_export_balance_error: float
    max_voltage_pu: float
    min_voltage_pu: float
    max_loading_percent: float
    validation_issue_count: int


@dataclass(frozen=True)
class PhysicalRawBuild:
    network_topology: tuple[NetworkTopologyElement, ...]
    raw_meter_readings: tuple[dict[str, Any], ...]
    raw_der_telemetry: tuple[dict[str, Any], ...]
    raw_network_states: tuple[dict[str, Any], ...]
    raw_context_events: tuple[dict[str, Any], ...]
    physical_violations: tuple[PhysicalViolation, ...]
    governance_triggers: tuple[GovernanceTrigger, ...]
    diagnostics: Mapping[str, PhysicalDiagnostics]

    def table_records(self) -> Mapping[str, tuple[dict[str, Any], ...]]:
        return {
            "raw_meter_reading": self.raw_meter_readings,
            "raw_der_telemetry": self.raw_der_telemetry,
            "raw_network_state": self.raw_network_states,
            "raw_context_event": self.raw_context_events,
        }


@dataclass(frozen=True)
class _PhysicalContext:
    resolved: ResolvedConfig
    scenario_id: str
    namespace: str
    rng: CounterRng
    contract: ContractSpec
    world: FederatedWorld
    backend_mode: str


class SolverHook(Protocol):
    """Future external-solver contract; no current execution path implements it."""

    solver_backend: str

    def solve_network_state(
        self,
        context: _PhysicalContext,
        topology: tuple[NetworkTopologyElement, ...],
        interval_start: datetime,
        net_power_by_region_kw: Mapping[str, float],
    ) -> tuple[dict[str, Any], ...]:
        ...


class BasePhysicalBackend:
    """Stable backend interface for S04 physical streams."""

    backend_mode = "procedural"
    generation_source = "controlled_synthetic"
    solver_backend = "procedural_analytic:v1"
    profile_reference = "controlled_synthetic.procedural.v1"

    def generate(self, context: _PhysicalContext) -> PhysicalRawBuild:
        topology = self.generate_topology(context)
        context_events = self.generate_context_events(context, topology)
        meter_rows = self.generate_meter_measurements(context, topology, context_events)
        der_rows = self.generate_der_telemetry(context, topology, context_events)
        network_rows = self.generate_network_states(context, topology, meter_rows)
        violations = self.extract_physical_violations(context, meter_rows, der_rows, network_rows)
        triggers = self.generate_governance_triggers(context, context_events, network_rows)
        build = PhysicalRawBuild(
            network_topology=topology,
            raw_meter_readings=meter_rows,
            raw_der_telemetry=der_rows,
            raw_network_states=network_rows,
            raw_context_events=context_events,
            physical_violations=violations,
            governance_triggers=triggers,
            diagnostics={
                context.scenario_id: _diagnostics(
                    context,
                    self.backend_mode,
                    topology,
                    meter_rows,
                    der_rows,
                    network_rows,
                    context_events,
                    violations,
                    triggers,
                )
            },
        )
        validate_physical_raw(build, context.resolved, world=context.world, contract=context.contract, scenario_ids=(context.scenario_id,))
        return build

    def load_kw(self, context: _PhysicalContext, cohort: Mapping[str, Any], interval_start: datetime, index: int) -> float:
        hour = interval_start.hour + interval_start.minute / 60.0
        dwelling = str(cohort["dwelling_type"])
        dwelling_base = {
            "apartment": 0.82,
            "single_family": 1.18,
            "rural_detached": 1.35,
            "mixed_residential": 1.05,
        }.get(dwelling, 1.0)
        morning = 0.22 * max(0.0, cos((hour - 7.0) * pi / 6.0))
        evening = 0.38 * max(0.0, cos((hour - 19.0) * pi / 7.0))
        overnight = 0.18 + 0.05 * cos((hour - 2.0) * pi / 12.0)
        jitter = (context.rng.uniform(f"load:{cohort['cohort_id']}", index) - 0.5) * 0.025
        return max(0.05, dwelling_base * (overnight + morning + evening + jitter))

    def solar_kw(self, context: _PhysicalContext, cohort: Mapping[str, Any], interval_start: datetime, index: int) -> float:
        hour = interval_start.hour + interval_start.minute / 60.0
        solar_shape = max(0.0, sin((hour - 6.0) * pi / 12.0))
        der_fraction = float(cohort["der_adoption_fraction"])
        cloud_factor = 0.84 + 0.08 * context.rng.uniform(f"solar:{cohort['cohort_id']}", index)
        return 4.5 * der_fraction * solar_shape * cloud_factor

    def generate_topology(self, context: _PhysicalContext) -> tuple[NetworkTopologyElement, ...]:
        elements: list[NetworkTopologyElement] = []
        for area in sorted(context.world.network_areas, key=lambda row: row["network_area_id"]):
            if area["scenario_id"] != context.scenario_id:
                continue
            capacity_kw = max(
                100.0,
                (int(area["represented_consumer_count"]) + int(area["represented_prosumer_count"])) * 1.8,
            )
            substation_id = deterministic_uuid(
                context.namespace,
                "network_topology_element",
                {"area": area["network_area_id"], "element_class": "substation"},
            )
            feeder_id = deterministic_uuid(
                context.namespace,
                "network_topology_element",
                {"area": area["network_area_id"], "element_class": "feeder"},
            )
            bus_id = deterministic_uuid(
                context.namespace,
                "network_topology_element",
                {"area": area["network_area_id"], "element_class": "bus"},
            )
            elements.extend(
                (
                    NetworkTopologyElement(
                        element_id=substation_id,
                        scenario_id=context.scenario_id,
                        region_id=str(area["region_id"]),
                        network_area_id=str(area["network_area_id"]),
                        element_class="substation",
                        parent_element_id=None,
                        nominal_voltage_v=None,
                        capacity_kw=capacity_kw * 1.20,
                    ),
                    NetworkTopologyElement(
                        element_id=feeder_id,
                        scenario_id=context.scenario_id,
                        region_id=str(area["region_id"]),
                        network_area_id=str(area["network_area_id"]),
                        element_class="feeder",
                        parent_element_id=substation_id,
                        nominal_voltage_v=None,
                        capacity_kw=capacity_kw,
                    ),
                    NetworkTopologyElement(
                        element_id=bus_id,
                        scenario_id=context.scenario_id,
                        region_id=str(area["region_id"]),
                        network_area_id=str(area["network_area_id"]),
                        element_class="bus",
                        parent_element_id=feeder_id,
                        nominal_voltage_v=230.0,
                        capacity_kw=capacity_kw * 0.55,
                    ),
                )
            )
        return tuple(sorted(elements, key=lambda item: item.element_id))

    def generate_context_events(
        self,
        context: _PhysicalContext,
        topology: tuple[NetworkTopologyElement, ...],
    ) -> tuple[dict[str, Any], ...]:
        rows: list[dict[str, Any]] = []
        start = _dt(context.resolved.run.horizon_start)
        end = _dt(context.resolved.run.horizon_end)
        midpoint = start + (end - start) / 2
        event_specs = (
            ("weather", start, end, 16.0, "degC", "clear"),
            ("tariff", start, end, 0.22, "currency_per_kWh", "time_of_use"),
            ("price", start, end, 68.0, "currency_per_MWh", "day_ahead"),
            ("outage", start + timedelta(hours=3), start + timedelta(hours=3, minutes=30), None, None, "planned_none"),
            ("dispatch", midpoint, midpoint + timedelta(minutes=30), 0.35, "per_unit", "der_flex_dispatch"),
            ("firmware", start + timedelta(hours=1), start + timedelta(hours=1, minutes=5), None, None, "meter_firmware_window"),
            ("clock", start + timedelta(hours=2), start + timedelta(hours=2, minutes=1), 0.0, "seconds", "clock_sync"),
            ("communications", start + timedelta(hours=4), start + timedelta(hours=4, minutes=10), None, None, "ami_backhaul_check"),
        )
        region_ids = sorted({element.region_id for element in topology})
        for region_id in region_ids:
            for ordinal, (event_class, event_start, event_end, numeric, unit, categorical) in enumerate(event_specs):
                event_id = deterministic_uuid(
                    context.namespace,
                    "raw_context_event",
                    {
                        "region_id": region_id,
                        "event_class": event_class,
                        "start": _iso_z(event_start),
                        "backend": self.backend_mode,
                    },
                )
                row = {
                    "context_event_id": event_id,
                    "scenario_id": context.scenario_id,
                    "event_class": event_class,
                    "region_id": region_id,
                    "asset_id": _asset_for_region(topology, region_id),
                    "start_time": _iso_z(event_start),
                    "end_time": _iso_z(event_end),
                    "numeric_value": _context_numeric(context, event_class, numeric, region_id, ordinal),
                    "unit": unit,
                    "categorical_value": categorical,
                    "generation_source": self.generation_source,
                    "calibration_source_id": _calibration_source(context, ordinal),
                }
                validate_record(context.contract, "raw_context_event", row)
                rows.append(row)
        return tuple(sorted(rows, key=lambda row: (row["region_id"], row["event_class"], row["context_event_id"])))

    def generate_meter_measurements(
        self,
        context: _PhysicalContext,
        topology: tuple[NetworkTopologyElement, ...],
        context_events: tuple[dict[str, Any], ...],
    ) -> tuple[dict[str, Any], ...]:
        rows: list[dict[str, Any]] = []
        interval_hours = context.resolved.physical.interval_seconds / 3600.0
        intervals = _intervals(context.resolved)
        cohorts = [
            cohort
            for cohort in sorted(context.world.prosumer_cohorts, key=lambda row: row["cohort_id"])
            if cohort["scenario_id"] == context.scenario_id
        ]
        outage_windows = _event_windows(context_events, "outage")
        for cohort in cohorts:
            represented = int(cohort["represented_consumer_count"]) + int(cohort["represented_prosumer_count"])
            meter_id = deterministic_uuid(
                context.namespace,
                "meter",
                {"cohort_id": cohort["cohort_id"], "backend": self.backend_mode},
            )
            for index, (interval_start, interval_end) in enumerate(intervals):
                load_energy = self.load_kw(context, cohort, interval_start, index) * interval_hours
                solar_energy = self.solar_kw(context, cohort, interval_start, index) * interval_hours
                import_energy = max(0.0, load_energy - solar_energy * 0.82)
                export_energy = max(0.0, solar_energy - load_energy * 0.72)
                outage = _active_event(outage_windows, str(cohort["region_id"]), interval_start)
                quality_flags = ["synthetic", "calibrated"]
                if outage:
                    quality_flags.extend(["outage", "estimated"])
                    import_energy *= 0.92
                    export_energy *= 0.90
                voltage_v = 230.0 * (1.0 - 0.012 * min(import_energy, 2.0) + 0.006 * min(export_energy, 1.0))
                row = {
                    "reading_id": deterministic_uuid(
                        context.namespace,
                        "raw_meter_reading",
                        {
                            "meter_id": meter_id,
                            "interval_start": _iso_z(interval_start),
                            "backend": self.backend_mode,
                        },
                    ),
                    "scenario_id": context.scenario_id,
                    "meter_id": meter_id,
                    "cohort_id": cohort["cohort_id"],
                    "region_id": cohort["region_id"],
                    "interval_start": _iso_z(interval_start),
                    "interval_end": _iso_z(interval_end),
                    "import_energy_kwh": round(import_energy, 6),
                    "export_energy_kwh": round(export_energy, 6),
                    "reactive_energy_kvarh": round(import_energy * 0.22, 6),
                    "voltage_v": round(voltage_v, 3),
                    "quality_flags": list(dict.fromkeys(quality_flags)),
                    "generation_backend": self.backend_mode,
                    "calibration_source_id": _calibration_source(context, index),
                    "represented_meter_count": float(represented),
                }
                validate_record(context.contract, "raw_meter_reading", row)
                rows.append(row)
        return tuple(sorted(rows, key=lambda row: (row["cohort_id"], row["interval_start"])))

    def generate_der_telemetry(
        self,
        context: _PhysicalContext,
        topology: tuple[NetworkTopologyElement, ...],
        context_events: tuple[dict[str, Any], ...],
    ) -> tuple[dict[str, Any], ...]:
        rows: list[dict[str, Any]] = []
        intervals = _intervals(context.resolved)
        dispatch_events = _event_windows(context_events, "dispatch")
        for cohort in sorted(context.world.prosumer_cohorts, key=lambda row: row["cohort_id"]):
            if cohort["scenario_id"] != context.scenario_id or int(cohort["represented_prosumer_count"]) <= 0:
                continue
            der_asset_id = deterministic_uuid(
                context.namespace,
                "der_asset",
                {"cohort_id": cohort["cohort_id"], "backend": self.backend_mode},
            )
            for index, (interval_start, _interval_end) in enumerate(intervals):
                power_kw = self.solar_kw(context, cohort, interval_start, index)
                dispatch = _active_event(dispatch_events, str(cohort["region_id"]), interval_start)
                control_mode = "self_consumption"
                trigger_event_id = None
                if dispatch is not None:
                    power_kw *= 0.88
                    control_mode = "grid_support"
                    trigger_event_id = str(dispatch["context_event_id"])
                soc = 0.52 + 0.28 * sin((interval_start.hour + interval_start.minute / 60.0 - 8.0) * pi / 12.0)
                row = {
                    "telemetry_id": deterministic_uuid(
                        context.namespace,
                        "raw_der_telemetry",
                        {
                            "der_asset_id": der_asset_id,
                            "timestamp": _iso_z(interval_start),
                            "backend": self.backend_mode,
                        },
                    ),
                    "scenario_id": context.scenario_id,
                    "der_asset_id": der_asset_id,
                    "timestamp": _iso_z(interval_start),
                    "active_power_kw": round(max(0.0, power_kw), 6),
                    "reactive_power_kvar": round(max(0.0, power_kw) * 0.08, 6),
                    "state_of_charge": round(max(0.05, min(0.95, soc)), 5),
                    "availability": True,
                    "control_mode": control_mode,
                    "quality_flags": ["synthetic", "calibrated"],
                    "trigger_event_id": trigger_event_id,
                }
                validate_record(context.contract, "raw_der_telemetry", row)
                rows.append(row)
        return tuple(sorted(rows, key=lambda row: (row["der_asset_id"], row["timestamp"])))

    def generate_network_states(
        self,
        context: _PhysicalContext,
        topology: tuple[NetworkTopologyElement, ...],
        meter_rows: tuple[dict[str, Any], ...],
    ) -> tuple[dict[str, Any], ...]:
        rows: list[dict[str, Any]] = []
        intervals = [start for start, _end in _intervals(context.resolved)]
        net_by_region_time = _net_power_by_region_time(meter_rows, context.resolved.physical.interval_seconds)
        for element in topology:
            for index, timestamp in enumerate(intervals):
                net_kw = net_by_region_time.get((element.region_id, _iso_z(timestamp)), 0.0)
                load_ratio = min(0.98, abs(net_kw) / max(element.capacity_kw, 1.0))
                voltage_pu = 1.0 - 0.030 * load_ratio if net_kw >= 0 else 1.0 + 0.016 * load_ratio
                loading_percent = min(99.0, 38.0 + load_ratio * 54.0)
                violation_flags: list[str] = []
                if voltage_pu < 0.95:
                    violation_flags.append("voltage_low")
                if voltage_pu > 1.05:
                    violation_flags.append("voltage_high")
                if loading_percent > 100.0:
                    violation_flags.append("loading_high")
                row = {
                    "network_state_id": deterministic_uuid(
                        context.namespace,
                        "raw_network_state",
                        {
                            "network_element_id": element.element_id,
                            "timestamp": _iso_z(timestamp),
                            "backend": self.backend_mode,
                        },
                    ),
                    "scenario_id": context.scenario_id,
                    "network_element_id": element.element_id,
                    "timestamp": _iso_z(timestamp),
                    "element_class": element.element_class,
                    "voltage_pu": round(voltage_pu, 6) if element.element_class in {"bus", "meter"} else None,
                    "loading_percent": round(loading_percent, 6) if element.element_class != "bus" else None,
                    "active_power_kw": round(net_kw, 6),
                    "reactive_power_kvar": round(net_kw * 0.22, 6),
                    "switch_open": False if element.element_class == "switch" else None,
                    "violation_flags": violation_flags,
                    "solver_backend": self.solver_backend,
                }
                validate_record(context.contract, "raw_network_state", row)
                rows.append(row)
        return tuple(sorted(rows, key=lambda row: (row["network_element_id"], row["timestamp"])))

    def extract_physical_violations(
        self,
        context: _PhysicalContext,
        meter_rows: tuple[dict[str, Any], ...],
        der_rows: tuple[dict[str, Any], ...],
        network_rows: tuple[dict[str, Any], ...],
    ) -> tuple[PhysicalViolation, ...]:
        violations: list[PhysicalViolation] = []
        for row in network_rows:
            for flag in row["violation_flags"]:
                violations.append(
                    PhysicalViolation(
                        violation_id=deterministic_uuid(
                            context.namespace,
                            "physical_violation",
                            {"source_id": row["network_state_id"], "flag": flag},
                        ),
                        scenario_id=context.scenario_id,
                        source_table="raw_network_state",
                        source_id=str(row["network_state_id"]),
                        violation_type=str(flag),
                        severity="error",
                        message=f"Network state emitted {flag}",
                    )
                )
        return tuple(sorted(violations, key=lambda item: item.violation_id))

    def generate_governance_triggers(
        self,
        context: _PhysicalContext,
        context_events: tuple[dict[str, Any], ...],
        network_rows: tuple[dict[str, Any], ...],
    ) -> tuple[GovernanceTrigger, ...]:
        triggers: list[GovernanceTrigger] = []
        event_map = {
            "outage": ("incident", "physical_outage"),
            "dispatch": ("operational", "der_dispatch"),
            "firmware": ("audit", "firmware_change"),
            "clock": ("correction", "clock_sync"),
            "communications": ("incident", "communications_status"),
        }
        for event in context_events:
            if event["event_class"] not in event_map:
                continue
            event_family, trigger_type = event_map[str(event["event_class"])]
            triggers.append(
                GovernanceTrigger(
                    trigger_id=deterministic_uuid(
                        context.namespace,
                        "governance_trigger",
                        {
                            "source_id": event["context_event_id"],
                            "trigger_type": trigger_type,
                        },
                    ),
                    scenario_id=context.scenario_id,
                    source_table="raw_context_event",
                    source_id=str(event["context_event_id"]),
                    trigger_type=trigger_type,
                    event_family=event_family,
                    region_id=str(event["region_id"]),
                    timestamp=str(event["start_time"]),
                    affected_cohort_id=_first_cohort_in_region(context.world, context.scenario_id, str(event["region_id"])),
                    description=f"{event['event_class']} context event can seed {event_family} governance arrivals",
                )
            )
        for row in network_rows:
            if not row["violation_flags"]:
                continue
            triggers.append(
                GovernanceTrigger(
                    trigger_id=deterministic_uuid(
                        context.namespace,
                        "governance_trigger",
                        {
                            "source_id": row["network_state_id"],
                            "trigger_type": "network_violation",
                        },
                    ),
                    scenario_id=context.scenario_id,
                    source_table="raw_network_state",
                    source_id=str(row["network_state_id"]),
                    trigger_type="network_violation",
                    event_family="incident",
                    region_id=_region_for_network_element(context.world, context.scenario_id, str(row["network_element_id"])),
                    timestamp=str(row["timestamp"]),
                    affected_cohort_id=None,
                    description="Network violation can seed incident governance arrivals",
                )
            )
        return tuple(sorted(triggers, key=lambda item: item.trigger_id))


class ProceduralPhysicalBackend(BasePhysicalBackend):
    backend_mode = "procedural"
    generation_source = "controlled_synthetic"
    solver_backend = "procedural_analytic:v1"
    profile_reference = "controlled_synthetic.procedural.v1"


class OpenSynthStyleSyntheticBackend(BasePhysicalBackend):
    """Controlled formula profile inspired by broad residential-load shapes."""

    backend_mode = "opensynth_style_synthetic"
    generation_source = "controlled_synthetic"
    solver_backend = "controlled_synthetic_profile_analytic:v1"
    profile_reference = "controlled_synthetic.opensynth_style.v1"

    def load_kw(self, context: _PhysicalContext, cohort: Mapping[str, Any], interval_start: datetime, index: int) -> float:
        hour = interval_start.hour + interval_start.minute / 60.0
        dwelling = str(cohort["dwelling_type"])
        base = {"apartment": 0.74, "single_family": 1.10, "rural_detached": 1.26}.get(dwelling, 0.98)
        evening_peak = 0.48 * max(0.0, cos((hour - 18.5) * pi / 6.0))
        daytime = 0.23 + 0.12 * max(0.0, cos((hour - 13.0) * pi / 8.0))
        residual = (
            context.rng.uniform(
                f"opensynth-style-synthetic-load:{cohort['cohort_id']}", index
            )
            - 0.5
        ) * 0.018
        return max(0.05, base * (daytime + evening_peak + residual))

    def solar_kw(self, context: _PhysicalContext, cohort: Mapping[str, Any], interval_start: datetime, index: int) -> float:
        hour = interval_start.hour + interval_start.minute / 60.0
        solar_shape = max(0.0, sin((hour - 5.8) * pi / 12.4))
        return 4.2 * float(cohort["der_adoption_fraction"]) * solar_shape


class SmartDsStyleSyntheticBackend(BasePhysicalBackend):
    """Controlled procedural topology style; no SMART-DS asset is imported."""

    backend_mode = "smart_ds_style_synthetic"
    generation_source = "controlled_synthetic"
    solver_backend = "controlled_synthetic_template_analytic:v1"
    profile_reference = "controlled_synthetic.smart_ds_style.v1"

    def generate_topology(self, context: _PhysicalContext) -> tuple[NetworkTopologyElement, ...]:
        base = list(super().generate_topology(context))
        switches: list[NetworkTopologyElement] = []
        for area in sorted(context.world.network_areas, key=lambda row: row["network_area_id"]):
            if area["scenario_id"] != context.scenario_id:
                continue
            switch_id = deterministic_uuid(
                context.namespace,
                "network_topology_element",
                {"area": area["network_area_id"], "element_class": "switch"},
            )
            parent = sorted(
                [
                    element
                    for element in base
                    if element.network_area_id == area["network_area_id"] and element.element_class == "feeder"
                ],
                key=lambda item: item.element_id,
            )[0]
            switches.append(
                NetworkTopologyElement(
                    element_id=switch_id,
                    scenario_id=context.scenario_id,
                    region_id=str(area["region_id"]),
                    network_area_id=str(area["network_area_id"]),
                    element_class="switch",
                    parent_element_id=parent.element_id,
                    nominal_voltage_v=None,
                    capacity_kw=parent.capacity_kw,
                )
            )
        return tuple(sorted((*base, *switches), key=lambda item: item.element_id))


BACKENDS: Mapping[str, type[BasePhysicalBackend]] = {
    "procedural": ProceduralPhysicalBackend,
    "opensynth_style_synthetic": OpenSynthStyleSyntheticBackend,
    "smart_ds_style_synthetic": SmartDsStyleSyntheticBackend,
}


def build_physical_raw(
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld | None = None,
    backend_mode: str | None = None,
    replicate_id: int = 0,
    scenario_ids: Iterable[str] | None = None,
    contract: ContractSpec | None = None,
) -> PhysicalRawBuild:
    """Build validated S04 physical raw streams for selected scenarios."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(scenario_ids) if scenario_ids is not None else tuple(resolved.run.selected_scenario_ids)
    if not selected:
        raise PhysicalValidationError("at least one scenario_id is required")
    unknown = sorted(set(selected) - set(resolved.run.selected_scenario_ids))
    if unknown:
        raise PhysicalValidationError(f"scenario_ids not selected in resolved config: {unknown}")
    if replicate_id < 0 or replicate_id >= resolved.run.replicate_count:
        raise PhysicalValidationError(
            f"replicate_id={replicate_id} is outside configured replicate_count={resolved.run.replicate_count}"
        )
    mode = backend_mode or resolved.physical.backend
    if mode not in BACKENDS:
        if mode in DEFERRED_EXTERNAL_PHYSICAL_BACKENDS:
            replacement = DEFERRED_EXTERNAL_PHYSICAL_BACKENDS[mode]
            raise PhysicalValidationError(
                f"external physical backend {mode!r} is deferred and unsupported; "
                f"use controlled synthetic profile {replacement!r}"
            )
        raise PhysicalValidationError(f"unsupported physical backend mode {mode!r}")
    expected_version, expected_analytic_backend = CONTROLLED_SYNTHETIC_PHYSICAL_PROFILES[
        mode
    ]
    backend_type = BACKENDS[mode]
    if (
        backend_type.solver_backend != expected_analytic_backend
        or (
            mode == resolved.physical.backend
            and resolved.physical.backend_version != expected_version
        )
    ):
        raise PhysicalValidationError(
            f"controlled physical profile contract mismatch for {mode!r}"
        )
    world_build = (
        world
        if world is not None
        else build_federated_world(
            resolved,
            replicate_id=replicate_id,
            scenario_ids=selected,
            contract=schema_contract,
        )
    )
    backend = backend_type()

    topologies: list[NetworkTopologyElement] = []
    meters: list[dict[str, Any]] = []
    ders: list[dict[str, Any]] = []
    networks: list[dict[str, Any]] = []
    contexts: list[dict[str, Any]] = []
    violations: list[PhysicalViolation] = []
    triggers: list[GovernanceTrigger] = []
    diagnostics: dict[str, PhysicalDiagnostics] = {}
    for scenario_id in sorted(selected):
        ctx = _physical_context(
            resolved,
            scenario_id,
            replicate_id,
            mode,
            world_build,
            schema_contract,
        )
        partial = backend.generate(ctx)
        topologies.extend(partial.network_topology)
        meters.extend(partial.raw_meter_readings)
        ders.extend(partial.raw_der_telemetry)
        networks.extend(partial.raw_network_states)
        contexts.extend(partial.raw_context_events)
        violations.extend(partial.physical_violations)
        triggers.extend(partial.governance_triggers)
        diagnostics[scenario_id] = partial.diagnostics[scenario_id]
    return PhysicalRawBuild(
        network_topology=tuple(sorted(topologies, key=lambda item: item.element_id)),
        raw_meter_readings=tuple(sorted(meters, key=lambda row: row["reading_id"])),
        raw_der_telemetry=tuple(sorted(ders, key=lambda row: row["telemetry_id"])),
        raw_network_states=tuple(sorted(networks, key=lambda row: row["network_state_id"])),
        raw_context_events=tuple(sorted(contexts, key=lambda row: row["context_event_id"])),
        physical_violations=tuple(sorted(violations, key=lambda item: item.violation_id)),
        governance_triggers=tuple(sorted(triggers, key=lambda item: item.trigger_id)),
        diagnostics=dict(sorted(diagnostics.items())),
    )


def _physical_context(
    resolved: ResolvedConfig,
    scenario_id: str,
    replicate_id: int,
    backend_mode: str,
    world: FederatedWorld,
    contract: ContractSpec,
) -> _PhysicalContext:
    plan = ResolvedRunPlan(
        run_id=resolved.run.run_id,
        scenario_id=scenario_id,
        replicate_id=replicate_id,
        config_sha256=resolved.config_sha256,
    )
    suffix = f"component={PHYSICAL_COMPONENT}|partition=global"
    for row in seed_stream_records_for_plan(resolved, plan, contract=contract):
        if row["stream_name"].endswith(suffix):
            return _PhysicalContext(
                resolved=resolved,
                scenario_id=scenario_id,
                namespace=str(row["deterministic_id_namespace"]),
                rng=CounterRng(str(row["seed_material_hex"])),
                contract=contract,
                world=world,
                backend_mode=backend_mode,
            )
    raise PhysicalValidationError(f"{scenario_id}: missing {PHYSICAL_COMPONENT} seed stream")


def validate_physical_raw(
    physical: PhysicalRawBuild,
    resolved: ResolvedConfig,
    *,
    world: FederatedWorld,
    contract: ContractSpec | None = None,
    scenario_ids: Iterable[str] | None = None,
) -> None:
    """Fail closed on schema, continuity, energy, DER, network and trigger invariants."""

    schema_contract = contract if contract is not None else load_contract()
    selected = tuple(scenario_ids) if scenario_ids is not None else tuple(resolved.run.selected_scenario_ids)
    cohort_keys = {(row["scenario_id"], row["cohort_id"]) for row in world.prosumer_cohorts}
    context_ids = {row["context_event_id"] for row in physical.raw_context_events}
    network_element_ids = {element.element_id for element in physical.network_topology}
    expected_interval_seconds = resolved.physical.interval_seconds
    if expected_interval_seconds <= 0:
        raise PhysicalValidationError("physical interval_seconds must be positive")
    if resolved.run.time_zone != "UTC":
        raise PhysicalValidationError("S04 physical raw generation currently requires UTC run time zone")
    _require_units(resolved)

    for table_name, rows in physical.table_records().items():
        for row in rows:
            validate_record(schema_contract, table_name, row)

    for row in physical.raw_meter_readings:
        if row["import_energy_kwh"] < 0 or row["export_energy_kwh"] < 0:
            raise PhysicalValidationError(f"meter reading {row['reading_id']}: import/export must be non-negative")
        if (row["scenario_id"], row["cohort_id"]) not in cohort_keys:
            raise PhysicalValidationError(f"meter reading {row['reading_id']}: unresolved cohort")
        if _dt(row["interval_end"]) <= _dt(row["interval_start"]):
            raise PhysicalValidationError(f"meter reading {row['reading_id']}: invalid interval")
        if (_dt(row["interval_end"]) - _dt(row["interval_start"])).total_seconds() != expected_interval_seconds:
            raise PhysicalValidationError(f"meter reading {row['reading_id']}: interval length mismatch")
        if row["represented_meter_count"] <= 0:
            raise PhysicalValidationError(f"meter reading {row['reading_id']}: represented_meter_count must be positive")

    _validate_interval_continuity(physical.raw_meter_readings, expected_interval_seconds)
    _validate_autocorrelation(physical.raw_meter_readings)

    for row in physical.raw_der_telemetry:
        if row["active_power_kw"] < -EPSILON:
            raise PhysicalValidationError(f"DER telemetry {row['telemetry_id']}: active power below modeled lower bound")
        if row["active_power_kw"] > 25.0:
            raise PhysicalValidationError(f"DER telemetry {row['telemetry_id']}: active power above procedural DER bound")
        if row["reactive_power_kvar"] is not None and row["reactive_power_kvar"] < -EPSILON:
            raise PhysicalValidationError(f"DER telemetry {row['telemetry_id']}: reactive power below bound")
        if row["state_of_charge"] is not None and not 0 <= row["state_of_charge"] <= 1:
            raise PhysicalValidationError(f"DER telemetry {row['telemetry_id']}: state_of_charge outside [0,1]")
        if row["trigger_event_id"] is not None and row["trigger_event_id"] not in context_ids:
            raise PhysicalValidationError(f"DER telemetry {row['telemetry_id']}: unresolved trigger event")

    _validate_export_der_balance(
        physical.raw_meter_readings,
        physical.raw_der_telemetry,
        resolved.physical.interval_seconds,
    )

    voltage_tol = float(resolved.physical.solver_tolerances.get("voltage_pu", 0.05))
    loading_limit = float(resolved.physical.solver_tolerances.get("loading_percent", 100.0))
    for row in physical.raw_network_states:
        if row["network_element_id"] not in network_element_ids:
            raise PhysicalValidationError(f"network state {row['network_state_id']}: unresolved topology element")
        if "solver_nonconvergence" in row["violation_flags"]:
            raise PhysicalValidationError(f"network state {row['network_state_id']}: solver nonconvergence")
        if row["voltage_pu"] is not None and not (1.0 - voltage_tol <= row["voltage_pu"] <= 1.0 + voltage_tol):
            raise PhysicalValidationError(f"network state {row['network_state_id']}: voltage outside tolerance")
        if row["loading_percent"] is not None and row["loading_percent"] > loading_limit:
            raise PhysicalValidationError(f"network state {row['network_state_id']}: loading exceeds threshold")

    for row in physical.raw_context_events:
        if row["end_time"] is not None:
            if _dt(row["end_time"]) < _dt(row["start_time"]):
                raise PhysicalValidationError(f"context event {row['context_event_id']}: end before start")
        if row["region_id"] not in resolved.world.regions:
            raise PhysicalValidationError(f"context event {row['context_event_id']}: unknown region")

    valid_sources = context_ids | {row["network_state_id"] for row in physical.raw_network_states}
    for trigger in physical.governance_triggers:
        if trigger.source_id not in valid_sources:
            raise PhysicalValidationError(f"governance trigger {trigger.trigger_id}: unresolved source")
        if trigger.event_family not in schema_contract.dictionary_values("event_family"):
            raise PhysicalValidationError(f"governance trigger {trigger.trigger_id}: unknown event family")

    for scenario_id in selected:
        scenario_meters = [row for row in physical.raw_meter_readings if row["scenario_id"] == scenario_id]
        if not scenario_meters:
            raise PhysicalValidationError(f"{scenario_id}: no meter readings")
        represented_by_interval = _represented_meter_by_interval(scenario_meters)
        cohort_total = sum(
            int(row["represented_consumer_count"]) + int(row["represented_prosumer_count"])
            for row in world.prosumer_cohorts
            if row["scenario_id"] == scenario_id
        )
        for timestamp, represented in represented_by_interval.items():
            if abs(represented - cohort_total) > EPSILON:
                raise PhysicalValidationError(
                    f"{scenario_id}: represented meter count {represented} at {timestamp} "
                    f"does not reconcile to {cohort_total}"
                )


def _diagnostics(
    context: _PhysicalContext,
    backend_mode: str,
    topology: tuple[NetworkTopologyElement, ...],
    meter_rows: tuple[dict[str, Any], ...],
    der_rows: tuple[dict[str, Any], ...],
    network_rows: tuple[dict[str, Any], ...],
    context_rows: tuple[dict[str, Any], ...],
    violations: tuple[PhysicalViolation, ...],
    triggers: tuple[GovernanceTrigger, ...],
) -> PhysicalDiagnostics:
    voltages = [row["voltage_pu"] for row in network_rows if row["voltage_pu"] is not None]
    loadings = [row["loading_percent"] for row in network_rows if row["loading_percent"] is not None]
    return PhysicalDiagnostics(
        scenario_id=context.scenario_id,
        backend_mode=backend_mode,
        meter_reading_count=len(meter_rows),
        der_telemetry_count=len(der_rows),
        network_state_count=len(network_rows),
        context_event_count=len(context_rows),
        trigger_count=len(triggers),
        topology_element_count=len(topology),
        represented_meter_total=max(_represented_meter_by_interval(meter_rows).values(), default=0.0),
        min_meter_autocorrelation=_min_autocorrelation(meter_rows),
        max_export_balance_error=_export_der_balance_error(
            meter_rows,
            der_rows,
            context.resolved.physical.interval_seconds,
        ),
        max_voltage_pu=max(voltages) if voltages else 0.0,
        min_voltage_pu=min(voltages) if voltages else 0.0,
        max_loading_percent=max(loadings) if loadings else 0.0,
        validation_issue_count=len(violations),
    )


def _dt(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise PhysicalValidationError(f"timestamp {value!r} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds") + "Z"


def _intervals(resolved: ResolvedConfig) -> tuple[tuple[datetime, datetime], ...]:
    start = _dt(resolved.run.horizon_start)
    end = _dt(resolved.run.horizon_end)
    step = timedelta(seconds=resolved.physical.interval_seconds)
    rows: list[tuple[datetime, datetime]] = []
    cursor = start
    while cursor < end:
        next_cursor = cursor + step
        if next_cursor > end:
            raise PhysicalValidationError("horizon is not divisible by physical interval_seconds")
        rows.append((cursor, next_cursor))
        cursor = next_cursor
    return tuple(rows)


def _calibration_source(context: _PhysicalContext, index: int) -> str | None:
    sources = tuple(context.resolved.physical.calibration_source_ids)
    if not sources:
        return None
    return sources[index % len(sources)]


def _context_numeric(
    context: _PhysicalContext,
    event_class: str,
    numeric: float | None,
    region_id: str,
    ordinal: int,
) -> float | None:
    if numeric is None:
        return None
    adjustment = (context.rng.uniform(f"context:{event_class}:{region_id}", ordinal) - 0.5) * 0.02
    return round(numeric * (1.0 + adjustment), 6)


def _asset_for_region(topology: tuple[NetworkTopologyElement, ...], region_id: str) -> str | None:
    candidates = [item for item in topology if item.region_id == region_id and item.element_class == "feeder"]
    if not candidates:
        candidates = [item for item in topology if item.region_id == region_id]
    return sorted(candidates, key=lambda item: item.element_id)[0].element_id if candidates else None


def _event_windows(context_events: Iterable[Mapping[str, Any]], event_class: str) -> Mapping[str, tuple[Mapping[str, Any], ...]]:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for event in context_events:
        if event["event_class"] == event_class:
            grouped.setdefault(str(event["region_id"]), []).append(event)
    return {key: tuple(values) for key, values in grouped.items()}


def _active_event(
    windows: Mapping[str, tuple[Mapping[str, Any], ...]],
    region_id: str,
    timestamp: datetime,
) -> Mapping[str, Any] | None:
    for event in windows.get(region_id, ()):
        end_raw = event["end_time"]
        if end_raw is None:
            continue
        if _dt(event["start_time"]) <= timestamp < _dt(end_raw):
            return event
    return None


def _net_power_by_region_time(meter_rows: Iterable[Mapping[str, Any]], interval_seconds: int) -> Mapping[tuple[str, str], float]:
    interval_hours = interval_seconds / 3600.0
    net: dict[tuple[str, str], float] = {}
    for row in meter_rows:
        key = (str(row["region_id"]), str(row["interval_start"]))
        net_kw = (float(row["import_energy_kwh"]) - float(row["export_energy_kwh"])) / interval_hours
        net[key] = net.get(key, 0.0) + net_kw * float(row["represented_meter_count"])
    return net


def _first_cohort_in_region(world: FederatedWorld, scenario_id: str, region_id: str) -> str | None:
    cohorts = [
        row
        for row in world.prosumer_cohorts
        if row["scenario_id"] == scenario_id and row["region_id"] == region_id
    ]
    if not cohorts:
        return None
    return str(sorted(cohorts, key=lambda row: row["cohort_id"])[0]["cohort_id"])


def _region_for_network_element(world: FederatedWorld, scenario_id: str, element_id: str) -> str:
    for area in world.network_areas:
        if area["scenario_id"] == scenario_id:
            return str(area["region_id"])
    raise PhysicalValidationError(f"{scenario_id}: cannot infer region for network element {element_id}")


def _validate_interval_continuity(rows: Iterable[Mapping[str, Any]], interval_seconds: int) -> None:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["meter_id"]), []).append(row)
    for meter_id, meter_rows in grouped.items():
        ordered = sorted(meter_rows, key=lambda row: row["interval_start"])
        for left, right in zip(ordered, ordered[1:]):
            if (_dt(right["interval_start"]) - _dt(left["interval_start"])).total_seconds() != interval_seconds:
                raise PhysicalValidationError(f"meter {meter_id}: interval continuity failure")
            if left["interval_end"] != right["interval_start"]:
                raise PhysicalValidationError(f"meter {meter_id}: interval end/start gap")


def _min_autocorrelation(rows: Iterable[Mapping[str, Any]]) -> float:
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["meter_id"]), []).append(row)
    values = [
        _lag1_autocorrelation(
            [
                float(row["import_energy_kwh"])
                for row in sorted(series, key=lambda item: item["interval_start"])
            ]
        )
        for series in grouped.values()
        if len(series) >= 4
    ]
    return min(values) if values else 1.0


def _validate_autocorrelation(rows: Iterable[Mapping[str, Any]]) -> None:
    minimum = _min_autocorrelation(rows)
    if minimum < 0.20:
        raise PhysicalValidationError(f"meter temporal autocorrelation too low: {minimum:.4f}")


def _lag1_autocorrelation(series: list[float]) -> float:
    left = series[:-1]
    right = series[1:]
    mean_left = sum(left) / len(left)
    mean_right = sum(right) / len(right)
    numerator = sum((a - mean_left) * (b - mean_right) for a, b in zip(left, right))
    denom_left = sum((a - mean_left) ** 2 for a in left)
    denom_right = sum((b - mean_right) ** 2 for b in right)
    if denom_left <= EPSILON or denom_right <= EPSILON:
        return 1.0
    return numerator / ((denom_left * denom_right) ** 0.5)


def _export_der_balance_error(
    meter_rows: Iterable[Mapping[str, Any]],
    der_rows: Iterable[Mapping[str, Any]],
    interval_seconds: int,
) -> float:
    # DER asset ids and meter ids are generated from cohort ids but intentionally
    # not reversible. Validate a conservative aggregate bound by timestamp.
    export_by_time: dict[str, float] = {}
    for row in meter_rows:
        export_by_time[str(row["interval_start"])] = export_by_time.get(str(row["interval_start"]), 0.0) + float(row["export_energy_kwh"])
    der_by_time: dict[str, float] = {}
    interval_hours = interval_seconds / 3600.0
    for row in der_rows:
        der_by_time[str(row["timestamp"])] = (
            der_by_time.get(str(row["timestamp"]), 0.0)
            + float(row["active_power_kw"]) * interval_hours
        )
    max_error = 0.0
    for timestamp, export in export_by_time.items():
        der_energy = der_by_time.get(timestamp, 0.0)
        max_error = max(max_error, max(0.0, export - der_energy - 0.0001))
    return max_error


def _validate_export_der_balance(
    meter_rows: Iterable[Mapping[str, Any]],
    der_rows: Iterable[Mapping[str, Any]],
    interval_seconds: int,
) -> None:
    error = _export_der_balance_error(meter_rows, der_rows, interval_seconds)
    if error > 0.05:
        raise PhysicalValidationError(f"export energy exceeds DER production bound by {error:.6f} kWh")


def _represented_meter_by_interval(rows: Iterable[Mapping[str, Any]]) -> Mapping[str, float]:
    counts: dict[str, float] = {}
    for row in rows:
        timestamp = str(row["interval_start"])
        counts[timestamp] = counts.get(timestamp, 0.0) + float(row["represented_meter_count"])
    return dict(sorted(counts.items()))


def _require_units(resolved: ResolvedConfig) -> None:
    units = resolved.physical.units
    expected = {"energy": "kWh", "power": "kW", "voltage": "V"}
    for key, expected_value in expected.items():
        observed = units.get(key)
        if observed != expected_value:
            raise PhysicalValidationError(f"physical units {key!r} must be {expected_value!r}, got {observed!r}")
