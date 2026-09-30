//! Investigation pipeline: temporal+geo graph assembly with bridge/cluster
//! detection, and a diminishing-information-gain stop criterion.
//!
//! The wider control loop this module names —
//! discover → normalise → entity-resolve → trace source lineage → geolocate →
//! generate pivots → score frontier → expand best candidates →
//! corroborate/contradict → build temporal+geo graph →
//! detect bridges/clusters → generate competing hypotheses →
//! seek discriminating evidence → promote/demote claims → recompute frontier →
//! stop on diminishing information gain — is already substantially
//! implemented by existing engines: [`crate::entity`] discovers, normalises,
//! and resolves entities; [`crate::evidence`] traces claim/hypothesis/
//! evidence/observation/source lineage; [`crate::coords`] geolocates;
//! [`crate::osint`] generates, scores, expands, and recomputes the search
//! frontier; and [`crate::fusion`]/[`crate::infrastructure`]/[`crate::website`]
//! corroborate or contradict evidence and generate/discriminate competing
//! hypotheses. Only two capabilities are named by the loop but implemented
//! nowhere: a graph that unifies caller-supplied relationship edges with
//! per-node temporal and geographic annotations and can be queried for
//! bridges/connected components, and an explicit rule that halts the loop
//! once several consecutive rounds all yield low marginal information gain.
//! [`crate::osint::SearchPriorityFactors::expected_information_gain`] only
//! weights one candidate pivot against others in the same ranking pass, and
//! [`crate::osint::SearchLimits`] only enforces static hard counts — neither
//! measures actual round-over-round yield, which is what
//! [`DiminishingGainStopCriterion`] adds.
//!
//! [`PipelineStage`] names every stage of the loop, in order, so a caller's
//! progress through it is explicit and testable; [`InvestigationPipeline`]
//! tracks that progress and applies the stop rule at the loop's stop-check
//! stage. Every other stage's actual domain work is delegated to the engine
//! that already implements it — this module does not duplicate discovery,
//! normalisation, entity resolution, provenance, or frontier logic.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::{Confidence, LatLon, Timestamp};

fn require_text(value: String, field: &'static str) -> Result<String, PipelineError> {
    crate::validation::require_text(value, field)
}

/// Failure conditions for pipeline graph assembly and control-loop tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    /// A required identifier or label was empty.
    EmptyValue {
        /// Name of the empty field.
        field: &'static str,
    },
    /// An edge referenced a node id never added to the graph.
    UnknownNode {
        /// The missing node id.
        node: String,
    },
    /// A stop-criterion window of zero rounds was requested.
    InvalidWindow,
    /// The pipeline has already halted; no further stages can be recorded.
    Stopped,
    /// The requested operation does not match the pipeline's current stage.
    WrongStage {
        /// The stage the pipeline is actually at.
        current: PipelineStage,
    },
}

impl fmt::Display for PipelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValue { field } => write!(formatter, "{field} must not be empty"),
            Self::UnknownNode { node } => {
                write!(formatter, "node `{node}` was never added to the graph")
            }
            Self::InvalidWindow => write!(formatter, "stop-criterion window must be positive"),
            Self::Stopped => write!(formatter, "the pipeline has already stopped"),
            Self::WrongStage { current } => {
                write!(formatter, "operation is not valid at stage `{current}`")
            }
        }
    }
}

impl std::error::Error for PipelineError {}

impl crate::validation::EmptyValueError for PipelineError {
    fn empty_value(field: &'static str) -> Self {
        Self::EmptyValue { field }
    }
}

/// Every named stage of the discover → ... → stop-on-diminishing-gain control
/// loop, in the directive's canonical order.
///
/// The final stage cycles back to [`Self::GeneratePivots`]: the directive is a
/// loop that keeps expanding and re-scoring its frontier until the stop
/// criterion fires, not a one-shot linear pipeline. Bootstrap stages
/// (`Discover` through `Geolocate`) describe how genuinely new raw material
/// enters the loop; a caller free of new raw material may re-enter a round at
/// [`Self::GeneratePivots`] directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PipelineStage {
    /// Ingest new raw material from any source.
    Discover,
    /// Reduce raw values to a canonical, comparable form.
    Normalise,
    /// Merge normalised observations into stable entity identities.
    EntityResolve,
    /// Record claim → hypothesis → evidence → observation → source lineage.
    TraceSourceLineage,
    /// Attach geographic coordinates where available.
    Geolocate,
    /// Propose new search pivots from resolved entities and lineage.
    GeneratePivots,
    /// Rank the active pivot frontier.
    ScoreFrontier,
    /// Execute the highest-ranked pivots.
    ExpandBestCandidates,
    /// Compare new findings against existing claims for support or conflict.
    Corroborate,
    /// Assemble resolved entities and relationships into one temporal+geo graph.
    BuildTemporalGeoGraph,
    /// Find bridge edges and connected-component clusters in that graph.
    DetectBridgesAndClusters,
    /// Propose competing explanations for the observed structure.
    GenerateCompetingHypotheses,
    /// Look for evidence that would separate the competing hypotheses.
    SeekDiscriminatingEvidence,
    /// Raise or lower claim confidence given the discriminating evidence.
    PromoteOrDemoteClaims,
    /// Recompute the search frontier given every claim change this round.
    RecomputeFrontier,
    /// Halt if recent rounds show diminishing information gain, else continue.
    StopOnDiminishingGain,
}

impl PipelineStage {
    /// All sixteen stages, in the directive's canonical order.
    pub const ALL: [Self; 16] = [
        Self::Discover,
        Self::Normalise,
        Self::EntityResolve,
        Self::TraceSourceLineage,
        Self::Geolocate,
        Self::GeneratePivots,
        Self::ScoreFrontier,
        Self::ExpandBestCandidates,
        Self::Corroborate,
        Self::BuildTemporalGeoGraph,
        Self::DetectBridgesAndClusters,
        Self::GenerateCompetingHypotheses,
        Self::SeekDiscriminatingEvidence,
        Self::PromoteOrDemoteClaims,
        Self::RecomputeFrontier,
        Self::StopOnDiminishingGain,
    ];

    /// Zero-based position in the canonical order.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        match self {
            Self::Discover => 0,
            Self::Normalise => 1,
            Self::EntityResolve => 2,
            Self::TraceSourceLineage => 3,
            Self::Geolocate => 4,
            Self::GeneratePivots => 5,
            Self::ScoreFrontier => 6,
            Self::ExpandBestCandidates => 7,
            Self::Corroborate => 8,
            Self::BuildTemporalGeoGraph => 9,
            Self::DetectBridgesAndClusters => 10,
            Self::GenerateCompetingHypotheses => 11,
            Self::SeekDiscriminatingEvidence => 12,
            Self::PromoteOrDemoteClaims => 13,
            Self::RecomputeFrontier => 14,
            Self::StopOnDiminishingGain => 15,
        }
    }

    /// The stage that follows this one; cycles from the last stage back to
    /// [`Self::GeneratePivots`] to continue the loop.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Discover => Self::Normalise,
            Self::Normalise => Self::EntityResolve,
            Self::EntityResolve => Self::TraceSourceLineage,
            Self::TraceSourceLineage => Self::Geolocate,
            Self::Geolocate => Self::GeneratePivots,
            Self::GeneratePivots => Self::ScoreFrontier,
            Self::ScoreFrontier => Self::ExpandBestCandidates,
            Self::ExpandBestCandidates => Self::Corroborate,
            Self::Corroborate => Self::BuildTemporalGeoGraph,
            Self::BuildTemporalGeoGraph => Self::DetectBridgesAndClusters,
            Self::DetectBridgesAndClusters => Self::GenerateCompetingHypotheses,
            Self::GenerateCompetingHypotheses => Self::SeekDiscriminatingEvidence,
            Self::SeekDiscriminatingEvidence => Self::PromoteOrDemoteClaims,
            Self::PromoteOrDemoteClaims => Self::RecomputeFrontier,
            Self::RecomputeFrontier => Self::StopOnDiminishingGain,
            Self::StopOnDiminishingGain => Self::GeneratePivots,
        }
    }
}

impl fmt::Display for PipelineStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Discover => "DISCOVER",
            Self::Normalise => "NORMALISE",
            Self::EntityResolve => "ENTITY-RESOLVE",
            Self::TraceSourceLineage => "TRACE SOURCE LINEAGE",
            Self::Geolocate => "GEOLOCATE",
            Self::GeneratePivots => "GENERATE PIVOTS",
            Self::ScoreFrontier => "SCORE FRONTIER",
            Self::ExpandBestCandidates => "EXPAND BEST CANDIDATES",
            Self::Corroborate => "CORROBORATE / CONTRADICT",
            Self::BuildTemporalGeoGraph => "BUILD TEMPORAL + GEO GRAPH",
            Self::DetectBridgesAndClusters => "DETECT BRIDGES / CLUSTERS",
            Self::GenerateCompetingHypotheses => "GENERATE COMPETING HYPOTHESES",
            Self::SeekDiscriminatingEvidence => "SEEK DISCRIMINATING EVIDENCE",
            Self::PromoteOrDemoteClaims => "PROMOTE / DEMOTE CLAIMS",
            Self::RecomputeFrontier => "RECOMPUTE FRONTIER",
            Self::StopOnDiminishingGain => "STOP ON DIMINISHING INFORMATION GAIN",
        })
    }
}

/// Node identifier in the investigation graph (an entity, record, or
/// observation id from any upstream engine).
pub type NodeId = String;

/// Undirected adjacency list keyed by node index: for each node, the list of
/// `(neighbor node index, edge index)` pairs reachable from it.
type Adjacency = Vec<Vec<(usize, usize)>>;

/// One relationship edge in the investigation graph.
#[derive(Debug, Clone, PartialEq)]
pub struct GraphEdge {
    from: NodeId,
    to: NodeId,
    label: String,
    observed_at: Timestamp,
    weight: Confidence,
}

impl GraphEdge {
    /// Node the edge starts from.
    #[must_use]
    pub fn from(&self) -> &str {
        &self.from
    }

    /// Node the edge points to.
    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }

    /// Edge label (predicate/relationship kind).
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// When the edge was observed.
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Edge strength.
    #[must_use]
    pub const fn weight(&self) -> Confidence {
        self.weight
    }
}

/// Earliest and latest timestamps spanned by a set of edges.
///
/// Unlike [`crate::TemporalInterval`] (a validated first-seen/observed-at/
/// last-seen window for a *single* observation), this simply tracks the
/// minimum and maximum timestamp across *many* edges, with no implied
/// observation-uncertainty semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporalSpan {
    earliest: Timestamp,
    latest: Timestamp,
}

impl TemporalSpan {
    /// Earliest timestamp in the span.
    #[must_use]
    pub const fn earliest(self) -> Timestamp {
        self.earliest
    }

    /// Latest timestamp in the span.
    #[must_use]
    pub const fn latest(self) -> Timestamp {
        self.latest
    }

    /// Inclusive duration of the span.
    #[must_use]
    pub const fn duration(self) -> Timestamp {
        self.latest.saturating_sub(self.earliest)
    }
}

/// A unified temporal+geo graph over caller-supplied nodes and edges.
///
/// Edges must reference nodes already added with [`Self::add_node`];
/// referencing an unknown node is rejected rather than silently creating it,
/// matching this crate's canonical-evidence convention of rejecting dangling
/// references. The graph is treated as undirected for connectivity purposes:
/// [`Self::clusters`] and [`Self::bridges`] answer "can you reach one node
/// from the other by following any edge in either direction", which is the
/// question that matters for corroboration-network structure, regardless of
/// which side of a relationship's `subject`/`object` a caller supplied first.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TemporalGeoGraph {
    nodes: BTreeSet<NodeId>,
    positions: BTreeMap<NodeId, LatLon>,
    edges: Vec<GraphEdge>,
}

impl TemporalGeoGraph {
    /// Creates an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds (or re-touches) a node, returning its canonical id.
    ///
    /// Calling this again for an id already present is not an error: a
    /// `Some` position updates the recorded position, while `None` leaves any
    /// previously recorded position untouched.
    ///
    /// # Errors
    /// Returns [`PipelineError::EmptyValue`] if `id` is empty or whitespace.
    pub fn add_node(
        &mut self,
        id: impl Into<String>,
        position: Option<LatLon>,
    ) -> Result<NodeId, PipelineError> {
        let id = require_text(id.into(), "node id")?;
        self.nodes.insert(id.clone());
        if let Some(position) = position {
            self.positions.insert(id.clone(), position);
        }
        Ok(id)
    }

    /// Adds an edge between two already-added nodes.
    ///
    /// # Errors
    /// Returns [`PipelineError::EmptyValue`] if `from`, `to`, or `label` is
    /// empty, or [`PipelineError::UnknownNode`] if either endpoint was never
    /// added with [`Self::add_node`].
    pub fn add_edge(
        &mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        label: impl Into<String>,
        observed_at: Timestamp,
        weight: Confidence,
    ) -> Result<(), PipelineError> {
        let from = require_text(from.into(), "edge from")?;
        let to = require_text(to.into(), "edge to")?;
        let label = require_text(label.into(), "edge label")?;
        if !self.nodes.contains(&from) {
            return Err(PipelineError::UnknownNode { node: from });
        }
        if !self.nodes.contains(&to) {
            return Err(PipelineError::UnknownNode { node: to });
        }
        self.edges.push(GraphEdge {
            from,
            to,
            label,
            observed_at,
            weight,
        });
        Ok(())
    }

    /// Number of distinct nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Recorded position for a node, if any.
    #[must_use]
    pub fn position(&self, id: &str) -> Option<LatLon> {
        self.positions.get(id).copied()
    }

    /// All edges currently in the graph.
    #[must_use]
    pub fn edges(&self) -> &[GraphEdge] {
        &self.edges
    }

    /// Builds an undirected adjacency list keyed by node index, alongside the
    /// stable, sorted node-id list the indices refer to.
    fn indexed_adjacency(&self) -> (Vec<&NodeId>, Adjacency) {
        let node_list: Vec<&NodeId> = self.nodes.iter().collect();
        let index_of: BTreeMap<&str, usize> = node_list
            .iter()
            .enumerate()
            .map(|(index, id)| (id.as_str(), index))
            .collect();
        let mut adjacency: Vec<Vec<(usize, usize)>> = vec![Vec::new(); node_list.len()];
        for (edge_index, edge) in self.edges.iter().enumerate() {
            let a = index_of[edge.from.as_str()];
            let b = index_of[edge.to.as_str()];
            adjacency[a].push((b, edge_index));
            adjacency[b].push((a, edge_index));
        }
        (node_list, adjacency)
    }

    /// Connected components ("clusters"), each a sorted list of node ids.
    ///
    /// Clusters are sorted by their smallest member id, and members within a
    /// cluster are sorted, so the result is deterministic regardless of
    /// insertion order.
    #[must_use]
    pub fn clusters(&self) -> Vec<Vec<NodeId>> {
        let (node_list, adjacency) = self.indexed_adjacency();
        let mut visited = vec![false; node_list.len()];
        let mut clusters = Vec::new();
        for start in 0..node_list.len() {
            if visited[start] {
                continue;
            }
            let mut members = Vec::new();
            let mut stack = vec![start];
            visited[start] = true;
            while let Some(node) = stack.pop() {
                members.push(node_list[node].clone());
                for &(neighbor, _edge_index) in &adjacency[node] {
                    if !visited[neighbor] {
                        visited[neighbor] = true;
                        stack.push(neighbor);
                    }
                }
            }
            members.sort();
            clusters.push(members);
        }
        clusters.sort();
        clusters
    }

    /// Bridge edges: edges whose removal would increase the number of
    /// connected components, found with Tarjan's linear-time bridge
    /// algorithm run iteratively (no recursion) over the undirected multigraph.
    ///
    /// Parallel edges between the same two nodes are correctly never reported
    /// as bridges, since removing one still leaves the other connecting them.
    #[must_use]
    pub fn bridges(&self) -> Vec<(NodeId, NodeId)> {
        let (node_list, adjacency) = self.indexed_adjacency();
        let node_count = node_list.len();
        let mut discovery: Vec<Option<u32>> = vec![None; node_count];
        let mut low: Vec<u32> = vec![0; node_count];
        let mut timer: u32 = 0;
        let mut bridge_edges: Vec<usize> = Vec::new();

        struct Frame {
            node: usize,
            parent: Option<usize>,
            parent_edge: Option<usize>,
            next_adjacency_index: usize,
        }

        for start in 0..node_count {
            if discovery[start].is_some() {
                continue;
            }
            discovery[start] = Some(timer);
            low[start] = timer;
            timer += 1;
            let mut stack = vec![Frame {
                node: start,
                parent: None,
                parent_edge: None,
                next_adjacency_index: 0,
            }];
            while let Some(frame_index) = stack.len().checked_sub(1) {
                let node = stack[frame_index].node;
                let position = stack[frame_index].next_adjacency_index;
                if position < adjacency[node].len() {
                    let (neighbor, edge_index) = adjacency[node][position];
                    stack[frame_index].next_adjacency_index += 1;
                    if Some(edge_index) == stack[frame_index].parent_edge {
                        // Skip exactly the edge instance used to arrive here,
                        // not every edge to the parent, so a parallel edge to
                        // the same parent is still explored (and therefore
                        // never misreported as a bridge).
                        continue;
                    }
                    if let Some(neighbor_discovery) = discovery[neighbor] {
                        low[node] = low[node].min(neighbor_discovery);
                    } else {
                        discovery[neighbor] = Some(timer);
                        low[neighbor] = timer;
                        timer += 1;
                        stack.push(Frame {
                            node: neighbor,
                            parent: Some(node),
                            parent_edge: Some(edge_index),
                            next_adjacency_index: 0,
                        });
                    }
                } else {
                    let finished = stack
                        .pop()
                        .expect("frame_index came from a non-empty stack");
                    if let Some(parent) = finished.parent {
                        low[parent] = low[parent].min(low[finished.node]);
                        let parent_discovery =
                            discovery[parent].expect("parent was discovered before its child");
                        if low[finished.node] > parent_discovery
                            && let Some(edge_index) = finished.parent_edge
                        {
                            bridge_edges.push(edge_index);
                        }
                    }
                }
            }
        }

        let mut result: Vec<(NodeId, NodeId)> = bridge_edges
            .into_iter()
            .map(|edge_index| {
                let edge = &self.edges[edge_index];
                (edge.from.clone(), edge.to.clone())
            })
            .collect();
        result.sort();
        result
    }

    /// Earliest/latest timestamp spanned by edges with both endpoints among
    /// `members`, or `None` if no such edge exists.
    #[must_use]
    pub fn cluster_temporal_span(&self, members: &[NodeId]) -> Option<TemporalSpan> {
        let members: BTreeSet<&str> = members.iter().map(String::as_str).collect();
        let mut timestamps = self.edges.iter().filter_map(|edge| {
            (members.contains(edge.from.as_str()) && members.contains(edge.to.as_str()))
                .then_some(edge.observed_at)
        });
        let first = timestamps.next()?;
        let (earliest, latest) = timestamps.fold((first, first), |(earliest, latest), value| {
            (earliest.min(value), latest.max(value))
        });
        Some(TemporalSpan { earliest, latest })
    }
}

/// One round's observed information-gain signal, recorded at the
/// [`PipelineStage::StopOnDiminishingGain`] stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InformationGainSample {
    /// Entities newly discovered or resolved this round.
    pub new_entities: u32,
    /// New corroborating relationships recorded this round.
    pub new_corroborations: u32,
    /// Claims promoted or demoted this round.
    pub claim_changes: u32,
}

impl InformationGainSample {
    /// Creates a sample from this round's counts.
    #[must_use]
    pub const fn new(new_entities: u32, new_corroborations: u32, claim_changes: u32) -> Self {
        Self {
            new_entities,
            new_corroborations,
            claim_changes,
        }
    }

    /// Total gain score: the sum of every count in this sample.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.new_entities as u64 + self.new_corroborations as u64 + self.claim_changes as u64
    }
}

/// Halts an investigation once several consecutive rounds all yield at or
/// below a minimum information-gain threshold.
///
/// This is deliberately distinct from [`crate::osint::SearchPriorityFactors`]'s
/// `expected_information_gain` (a static per-pivot ranking weight) and
/// [`crate::osint::SearchLimits`] (static hard resource caps): this tracks the
/// actual yield each round produced and only stops once a full window of
/// consecutive rounds all underperformed, so one unproductive round never
/// halts an otherwise-productive investigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiminishingGainStopCriterion {
    window: usize,
    min_gain: u64,
    history: VecDeque<u64>,
}

impl DiminishingGainStopCriterion {
    /// Creates a stop criterion over the last `window` rounds, stopping once
    /// every one of them has a gain at or below `min_gain`.
    ///
    /// # Errors
    /// Returns [`PipelineError::InvalidWindow`] if `window` is zero.
    pub fn new(window: usize, min_gain: u64) -> Result<Self, PipelineError> {
        if window == 0 {
            return Err(PipelineError::InvalidWindow);
        }
        Ok(Self {
            window,
            min_gain,
            history: VecDeque::with_capacity(window),
        })
    }

    /// Records one round's sample, evicting the oldest recorded round once
    /// the window is full.
    pub fn record(&mut self, sample: InformationGainSample) {
        if self.history.len() == self.window {
            self.history.pop_front();
        }
        self.history.push_back(sample.total());
    }

    /// Whether the last `window` rounds all had gain at or below `min_gain`.
    ///
    /// Always `false` until at least `window` rounds have been recorded.
    #[must_use]
    pub fn should_stop(&self) -> bool {
        self.history.len() == self.window && self.history.iter().all(|&gain| gain <= self.min_gain)
    }

    /// Number of rounds currently recorded (capped at `window`).
    #[must_use]
    pub fn rounds_recorded(&self) -> usize {
        self.history.len()
    }

    /// Configured window size.
    #[must_use]
    pub const fn window(&self) -> usize {
        self.window
    }

    /// Configured minimum-gain threshold.
    #[must_use]
    pub const fn min_gain(&self) -> u64 {
        self.min_gain
    }
}

/// Tracks one investigation's progress through the sixteen-stage control loop
/// and applies [`DiminishingGainStopCriterion`] at the loop's stop-check stage.
///
/// [`Self::advance`] moves linearly through every stage up to (but not
/// through) [`PipelineStage::StopOnDiminishingGain`]; that stage is only
/// resolved by [`Self::complete_round`], which records the round's
/// [`InformationGainSample`] and decides whether to halt or loop back to
/// [`PipelineStage::GeneratePivots`] for another round.
#[derive(Debug, Clone, PartialEq)]
pub struct InvestigationPipeline {
    stage: PipelineStage,
    log: Vec<(PipelineStage, Timestamp)>,
    stop_criterion: DiminishingGainStopCriterion,
    rounds_completed: u32,
    stopped: bool,
}

impl InvestigationPipeline {
    /// Creates a new pipeline starting at [`PipelineStage::Discover`], with a
    /// stop criterion over the given window and minimum-gain threshold.
    ///
    /// # Errors
    /// Returns [`PipelineError::InvalidWindow`] if `window` is zero.
    pub fn new(window: usize, min_gain: u64) -> Result<Self, PipelineError> {
        Ok(Self {
            stage: PipelineStage::Discover,
            log: Vec::new(),
            stop_criterion: DiminishingGainStopCriterion::new(window, min_gain)?,
            rounds_completed: 0,
            stopped: false,
        })
    }

    /// The stage the pipeline is currently at.
    #[must_use]
    pub const fn current_stage(&self) -> PipelineStage {
        self.stage
    }

    /// Every stage reached so far, with the timestamp it was reached at.
    #[must_use]
    pub fn stage_log(&self) -> &[(PipelineStage, Timestamp)] {
        &self.log
    }

    /// Number of rounds completed via [`Self::complete_round`].
    #[must_use]
    pub const fn rounds_completed(&self) -> u32 {
        self.rounds_completed
    }

    /// Whether the pipeline has halted.
    #[must_use]
    pub const fn stopped(&self) -> bool {
        self.stopped
    }

    /// Read-only access to the stop criterion's own state.
    #[must_use]
    pub const fn stop_criterion(&self) -> &DiminishingGainStopCriterion {
        &self.stop_criterion
    }

    /// Records the current stage as reached at `observed_at` and advances to
    /// its successor.
    ///
    /// # Errors
    /// Returns [`PipelineError::Stopped`] if the pipeline already halted, or
    /// [`PipelineError::WrongStage`] if the pipeline is at
    /// [`PipelineStage::StopOnDiminishingGain`] (use [`Self::complete_round`]
    /// there instead).
    pub fn advance(&mut self, observed_at: Timestamp) -> Result<PipelineStage, PipelineError> {
        if self.stopped {
            return Err(PipelineError::Stopped);
        }
        if self.stage == PipelineStage::StopOnDiminishingGain {
            return Err(PipelineError::WrongStage {
                current: self.stage,
            });
        }
        self.log.push((self.stage, observed_at));
        self.stage = self.stage.next();
        Ok(self.stage)
    }

    /// Resolves the [`PipelineStage::StopOnDiminishingGain`] stage: records
    /// `sample`, evaluates the stop criterion, and either halts the pipeline
    /// or loops it back to [`PipelineStage::GeneratePivots`] for another round.
    ///
    /// Returns `true` if the pipeline has now stopped.
    ///
    /// # Errors
    /// Returns [`PipelineError::Stopped`] if the pipeline already halted, or
    /// [`PipelineError::WrongStage`] if the pipeline is not currently at
    /// [`PipelineStage::StopOnDiminishingGain`].
    pub fn complete_round(
        &mut self,
        sample: InformationGainSample,
        observed_at: Timestamp,
    ) -> Result<bool, PipelineError> {
        if self.stopped {
            return Err(PipelineError::Stopped);
        }
        if self.stage != PipelineStage::StopOnDiminishingGain {
            return Err(PipelineError::WrongStage {
                current: self.stage,
            });
        }
        self.log.push((self.stage, observed_at));
        self.stop_criterion.record(sample);
        self.rounds_completed += 1;
        self.stopped = self.stop_criterion.should_stop();
        self.stage = self.stage.next();
        Ok(self.stopped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_stage_ordinal_matches_all_array_position() {
        for (index, stage) in PipelineStage::ALL.iter().enumerate() {
            assert_eq!(stage.ordinal(), index);
        }
    }

    #[test]
    fn pipeline_stage_next_cycles_back_from_stop_to_generate_pivots() {
        assert_eq!(
            PipelineStage::StopOnDiminishingGain.next(),
            PipelineStage::GeneratePivots
        );
    }

    #[test]
    fn pipeline_stage_next_is_linear_through_the_whole_directive() {
        for pair in PipelineStage::ALL.windows(2) {
            assert_eq!(pair[0].next(), pair[1]);
        }
    }

    #[test]
    fn pipeline_stage_display_matches_the_directive_wording() {
        assert_eq!(PipelineStage::Discover.to_string(), "DISCOVER");
        assert_eq!(
            PipelineStage::TraceSourceLineage.to_string(),
            "TRACE SOURCE LINEAGE"
        );
        assert_eq!(
            PipelineStage::BuildTemporalGeoGraph.to_string(),
            "BUILD TEMPORAL + GEO GRAPH"
        );
        assert_eq!(
            PipelineStage::DetectBridgesAndClusters.to_string(),
            "DETECT BRIDGES / CLUSTERS"
        );
        assert_eq!(
            PipelineStage::StopOnDiminishingGain.to_string(),
            "STOP ON DIMINISHING INFORMATION GAIN"
        );
    }
}
