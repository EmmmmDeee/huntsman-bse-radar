//! Regression tests for the investigation pipeline: temporal+geo graph
//! assembly, bridge/cluster detection, the diminishing-information-gain stop
//! criterion, and control-loop stage tracking.

use bleradar_core::{
    Confidence, DiminishingGainStopCriterion, InformationGainSample, InvestigationPipeline, LatLon,
    PipelineError, PipelineStage, TemporalGeoGraph,
};

fn conf(value: u8) -> Confidence {
    Confidence::new(value)
}

#[test]
fn add_node_rejects_empty_id() {
    let mut graph = TemporalGeoGraph::new();
    assert_eq!(
        graph.add_node("", None),
        Err(PipelineError::EmptyValue { field: "node id" })
    );
    assert_eq!(
        graph.add_node("   ", None),
        Err(PipelineError::EmptyValue { field: "node id" })
    );
}

#[test]
fn add_edge_rejects_unknown_endpoints() {
    let mut graph = TemporalGeoGraph::new();
    graph.add_node("a", None).unwrap();
    assert_eq!(
        graph.add_edge("a", "b", "corroborates", 1, conf(50)),
        Err(PipelineError::UnknownNode { node: "b".into() })
    );
    assert_eq!(
        graph.add_edge("z", "a", "corroborates", 1, conf(50)),
        Err(PipelineError::UnknownNode { node: "z".into() })
    );
}

#[test]
fn add_edge_rejects_empty_label() {
    let mut graph = TemporalGeoGraph::new();
    graph.add_node("a", None).unwrap();
    graph.add_node("b", None).unwrap();
    assert_eq!(
        graph.add_edge("a", "b", "", 1, conf(50)),
        Err(PipelineError::EmptyValue {
            field: "edge label"
        })
    );
}

#[test]
fn add_node_upsert_preserves_position_when_re_added_without_one() {
    let mut graph = TemporalGeoGraph::new();
    let position = LatLon::new(-26.8, 152.8).unwrap();
    graph.add_node("a", Some(position)).unwrap();
    graph.add_node("a", None).unwrap();
    assert_eq!(graph.position("a"), Some(position));
    assert_eq!(graph.node_count(), 1);
}

#[test]
fn add_node_upsert_updates_position_when_re_added_with_a_new_one() {
    let mut graph = TemporalGeoGraph::new();
    let first = LatLon::new(-26.8, 152.8).unwrap();
    let second = LatLon::new(10.0, 10.0).unwrap();
    graph.add_node("a", Some(first)).unwrap();
    graph.add_node("a", Some(second)).unwrap();
    assert_eq!(graph.position("a"), Some(second));
}

#[test]
fn clusters_groups_disjoint_components_and_isolates_singletons() {
    let mut graph = TemporalGeoGraph::new();
    for id in ["a", "b", "c", "d", "e"] {
        graph.add_node(id, None).unwrap();
    }
    graph.add_edge("a", "b", "link", 1, conf(50)).unwrap();
    graph.add_edge("b", "c", "link", 2, conf(50)).unwrap();
    graph.add_edge("d", "e", "link", 3, conf(50)).unwrap();
    // "f" stays isolated: no edges at all.
    graph.add_node("f", None).unwrap();

    let clusters = graph.clusters();
    assert_eq!(
        clusters,
        vec![
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            vec!["d".to_string(), "e".to_string()],
            vec!["f".to_string()],
        ]
    );
}

#[test]
fn bridges_reports_every_edge_of_a_simple_path() {
    let mut graph = TemporalGeoGraph::new();
    for id in ["a", "b", "c"] {
        graph.add_node(id, None).unwrap();
    }
    graph.add_edge("a", "b", "link", 1, conf(50)).unwrap();
    graph.add_edge("b", "c", "link", 2, conf(50)).unwrap();

    assert_eq!(
        graph.bridges(),
        vec![
            ("a".to_string(), "b".to_string()),
            ("b".to_string(), "c".to_string()),
        ]
    );
}

#[test]
fn bridges_reports_none_for_a_triangle_cycle() {
    let mut graph = TemporalGeoGraph::new();
    for id in ["a", "b", "c"] {
        graph.add_node(id, None).unwrap();
    }
    graph.add_edge("a", "b", "link", 1, conf(50)).unwrap();
    graph.add_edge("b", "c", "link", 2, conf(50)).unwrap();
    graph.add_edge("c", "a", "link", 3, conf(50)).unwrap();

    assert_eq!(graph.bridges(), Vec::<(String, String)>::new());
}

#[test]
fn bridges_finds_only_the_single_edge_joining_two_triangles() {
    // Classic textbook case: two otherwise-cyclic clusters joined by exactly
    // one edge. Only that joining edge is a bridge; the two triangles'
    // internal edges are each on a cycle and must not be reported.
    let mut graph = TemporalGeoGraph::new();
    for id in ["a1", "a2", "a3", "b1", "b2", "b3"] {
        graph.add_node(id, None).unwrap();
    }
    graph.add_edge("a1", "a2", "link", 1, conf(50)).unwrap();
    graph.add_edge("a2", "a3", "link", 2, conf(50)).unwrap();
    graph.add_edge("a3", "a1", "link", 3, conf(50)).unwrap();
    graph.add_edge("b1", "b2", "link", 4, conf(50)).unwrap();
    graph.add_edge("b2", "b3", "link", 5, conf(50)).unwrap();
    graph.add_edge("b3", "b1", "link", 6, conf(50)).unwrap();
    graph.add_edge("a3", "b1", "bridge", 7, conf(90)).unwrap();

    assert_eq!(graph.bridges(), vec![("a3".to_string(), "b1".to_string())]);
}

#[test]
fn bridges_ignores_parallel_edges_between_the_same_two_nodes() {
    // Two distinct relationships between the same pair of nodes: removing
    // either one alone still leaves the other connecting them, so neither is
    // a bridge, even though a single such edge in isolation would be one.
    let mut graph = TemporalGeoGraph::new();
    graph.add_node("a", None).unwrap();
    graph.add_node("b", None).unwrap();
    graph
        .add_edge("a", "b", "seen-together", 1, conf(50))
        .unwrap();
    graph
        .add_edge("a", "b", "same-source", 2, conf(60))
        .unwrap();

    assert_eq!(graph.bridges(), Vec::<(String, String)>::new());
}

#[test]
fn cluster_temporal_span_covers_only_edges_within_the_cluster() {
    let mut graph = TemporalGeoGraph::new();
    for id in ["a", "b", "c"] {
        graph.add_node(id, None).unwrap();
    }
    graph.add_edge("a", "b", "link", 100, conf(50)).unwrap();
    graph.add_edge("b", "c", "link", 500, conf(50)).unwrap();

    let span = graph
        .cluster_temporal_span(&["a".to_string(), "b".to_string(), "c".to_string()])
        .unwrap();
    assert_eq!(span.earliest(), 100);
    assert_eq!(span.latest(), 500);
    assert_eq!(span.duration(), 400);
}

#[test]
fn cluster_temporal_span_is_none_for_a_cluster_with_no_qualifying_edge() {
    let mut graph = TemporalGeoGraph::new();
    graph.add_node("isolated", None).unwrap();
    assert_eq!(graph.cluster_temporal_span(&["isolated".to_string()]), None);
}

#[test]
fn information_gain_sample_totals_every_count() {
    let sample = InformationGainSample::new(2, 3, 4);
    assert_eq!(sample.total(), 9);
}

#[test]
fn stop_criterion_rejects_zero_window() {
    assert_eq!(
        DiminishingGainStopCriterion::new(0, 5),
        Err(PipelineError::InvalidWindow)
    );
}

#[test]
fn stop_criterion_does_not_stop_before_the_window_fills() {
    let mut criterion = DiminishingGainStopCriterion::new(3, 1).unwrap();
    criterion.record(InformationGainSample::new(0, 0, 0));
    assert!(!criterion.should_stop());
    criterion.record(InformationGainSample::new(0, 0, 0));
    assert!(!criterion.should_stop());
    assert_eq!(criterion.rounds_recorded(), 2);
}

#[test]
fn stop_criterion_stops_once_every_round_in_the_window_is_low_gain() {
    let mut criterion = DiminishingGainStopCriterion::new(3, 1).unwrap();
    for _ in 0..3 {
        criterion.record(InformationGainSample::new(0, 1, 0));
    }
    assert_eq!(criterion.rounds_recorded(), 3);
    assert!(criterion.should_stop());
}

#[test]
fn stop_criterion_keeps_going_while_any_round_in_the_window_is_high_gain() {
    let mut criterion = DiminishingGainStopCriterion::new(3, 1).unwrap();
    criterion.record(InformationGainSample::new(0, 1, 0));
    criterion.record(InformationGainSample::new(10, 0, 0));
    criterion.record(InformationGainSample::new(0, 1, 0));
    assert!(!criterion.should_stop());
}

#[test]
fn stop_criterion_recovers_once_a_high_gain_round_slides_out_of_the_window() {
    let mut criterion = DiminishingGainStopCriterion::new(2, 1).unwrap();
    criterion.record(InformationGainSample::new(10, 0, 0));
    criterion.record(InformationGainSample::new(0, 1, 0));
    assert!(!criterion.should_stop());
    // The high-gain round ages out of the two-round window here.
    criterion.record(InformationGainSample::new(0, 1, 0));
    assert!(criterion.should_stop());
}

#[test]
fn investigation_pipeline_new_propagates_invalid_window() {
    assert_eq!(
        InvestigationPipeline::new(0, 1),
        Err(PipelineError::InvalidWindow)
    );
}

#[test]
fn investigation_pipeline_starts_at_discover() {
    let pipeline = InvestigationPipeline::new(2, 1).unwrap();
    assert_eq!(pipeline.current_stage(), PipelineStage::Discover);
    assert_eq!(pipeline.rounds_completed(), 0);
    assert!(!pipeline.stopped());
}

#[test]
fn investigation_pipeline_advance_reaches_the_stop_check_stage_in_order() {
    let mut pipeline = InvestigationPipeline::new(2, 1).unwrap();
    for (index, stage) in PipelineStage::ALL.iter().enumerate() {
        if *stage == PipelineStage::StopOnDiminishingGain {
            break;
        }
        assert_eq!(pipeline.current_stage(), *stage);
        let next = pipeline.advance(u64::try_from(index).unwrap()).unwrap();
        assert_eq!(next, stage.next());
    }
    assert_eq!(
        pipeline.current_stage(),
        PipelineStage::StopOnDiminishingGain
    );
    assert_eq!(pipeline.stage_log().len(), 15);
    assert_eq!(pipeline.stage_log()[0], (PipelineStage::Discover, 0));
}

#[test]
fn investigation_pipeline_advance_at_the_stop_check_stage_is_rejected() {
    let mut pipeline = InvestigationPipeline::new(1, 1).unwrap();
    for stage in PipelineStage::ALL {
        if stage == PipelineStage::StopOnDiminishingGain {
            break;
        }
        pipeline.advance(0).unwrap();
    }
    assert_eq!(
        pipeline.advance(0),
        Err(PipelineError::WrongStage {
            current: PipelineStage::StopOnDiminishingGain
        })
    );
}

#[test]
fn investigation_pipeline_complete_round_elsewhere_is_rejected() {
    let mut pipeline = InvestigationPipeline::new(1, 1).unwrap();
    assert_eq!(pipeline.current_stage(), PipelineStage::Discover);
    assert_eq!(
        pipeline.complete_round(InformationGainSample::new(0, 0, 0), 0),
        Err(PipelineError::WrongStage {
            current: PipelineStage::Discover
        })
    );
}

fn drive_to_stop_check(pipeline: &mut InvestigationPipeline) {
    while pipeline.current_stage() != PipelineStage::StopOnDiminishingGain {
        pipeline.advance(0).unwrap();
    }
}

#[test]
fn investigation_pipeline_complete_round_loops_back_when_gain_is_still_high() {
    let mut pipeline = InvestigationPipeline::new(2, 1).unwrap();
    drive_to_stop_check(&mut pipeline);
    let stopped = pipeline
        .complete_round(InformationGainSample::new(5, 0, 0), 0)
        .unwrap();
    assert!(!stopped);
    assert!(!pipeline.stopped());
    assert_eq!(pipeline.current_stage(), PipelineStage::GeneratePivots);
    assert_eq!(pipeline.rounds_completed(), 1);
}

#[test]
fn investigation_pipeline_stops_after_enough_low_gain_rounds_and_then_rejects_further_calls() {
    let mut pipeline = InvestigationPipeline::new(2, 0).unwrap();
    for round in 0..2 {
        drive_to_stop_check(&mut pipeline);
        let stopped = pipeline
            .complete_round(InformationGainSample::new(0, 0, 0), round)
            .unwrap();
        assert_eq!(stopped, round == 1);
    }
    assert!(pipeline.stopped());
    assert_eq!(pipeline.rounds_completed(), 2);
    assert_eq!(pipeline.advance(0), Err(PipelineError::Stopped));
    assert_eq!(
        pipeline.complete_round(InformationGainSample::new(0, 0, 0), 0),
        Err(PipelineError::Stopped)
    );
}

#[test]
fn pipeline_error_variants_implement_display_and_error() {
    let errors: Vec<PipelineError> = vec![
        PipelineError::EmptyValue { field: "node id" },
        PipelineError::UnknownNode {
            node: "x".to_string(),
        },
        PipelineError::InvalidWindow,
        PipelineError::Stopped,
        PipelineError::WrongStage {
            current: PipelineStage::Discover,
        },
    ];
    for error in errors {
        let rendered = error.to_string();
        assert!(!rendered.is_empty());
        let _: &dyn std::error::Error = &error;
    }
}

// ── Differential oracle for clusters()/bridges() (2026-09-10, decision #61) ──
//
// An edge is a bridge iff removing it increases the number of connected
// components. That definition is trivially computable with union-find, so it
// is an independent reference for the iterative, multigraph-safe Tarjan
// search: random graphs with self-loops and parallel edges are exactly the
// inputs where bridge finders go wrong. 50,000 graphs matched on the day this
// was added; every `cargo test` re-checks a deterministic 2,000-graph sample.

mod differential {
    use std::collections::{BTreeMap, BTreeSet};

    pub struct Rng(pub u64);

    impl Rng {
        pub fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        pub fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    fn find(parent: &mut [usize], x: usize) -> usize {
        let mut root = x;
        while parent[root] != root {
            root = parent[root];
        }
        let mut cursor = x;
        while parent[cursor] != root {
            let next = parent[cursor];
            parent[cursor] = root;
            cursor = next;
        }
        root
    }

    /// Component label of every node with edge `skip` (if any) removed.
    pub fn components(n: usize, edges: &[(usize, usize)], skip: Option<usize>) -> Vec<usize> {
        let mut parent: Vec<usize> = (0..n).collect();
        for (i, &(a, b)) in edges.iter().enumerate() {
            if Some(i) == skip {
                continue;
            }
            let (ra, rb) = (find(&mut parent, a), find(&mut parent, b));
            if ra != rb {
                parent[ra] = rb;
            }
        }
        (0..n).map(|v| find(&mut parent, v)).collect()
    }

    pub fn component_sets(names: &[String], labels: &[usize]) -> BTreeSet<BTreeSet<String>> {
        let mut by_label: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
        for (v, label) in labels.iter().enumerate() {
            by_label.entry(*label).or_default().insert(names[v].clone());
        }
        by_label.into_values().collect()
    }

    pub fn distinct(labels: &[usize]) -> usize {
        labels.iter().collect::<BTreeSet<_>>().len()
    }
}

#[test]
fn clusters_and_bridges_match_a_brute_force_reference_on_random_multigraphs() {
    use differential::{Rng, component_sets, components, distinct};
    use std::collections::BTreeSet;

    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for graph_index in 0..2_000 {
        let n = 1 + rng.below(9);
        let m = rng.below(14);
        let mut edges: Vec<(usize, usize)> = Vec::with_capacity(m + 1);
        for _ in 0..m {
            let a = rng.below(n);
            // Some self-loops, and a duplicated edge on every other graph so
            // parallel edges (never bridges) are always represented.
            let b = if rng.below(6) == 0 { a } else { rng.below(n) };
            edges.push((a, b));
        }
        if !edges.is_empty() && rng.below(2) == 0 {
            let duplicate = edges[rng.below(edges.len())];
            edges.push(duplicate);
        }

        let names: Vec<String> = (0..n).map(|i| format!("n{i}")).collect();
        let mut graph = TemporalGeoGraph::new();
        for name in &names {
            graph.add_node(name.clone(), None).unwrap();
        }
        for (i, &(a, b)) in edges.iter().enumerate() {
            graph
                .add_edge(&names[a], &names[b], format!("e{i}"), i as u64, conf(50))
                .unwrap();
        }

        let labels = components(n, &edges, None);
        let expected_clusters = component_sets(&names, &labels);
        let actual_clusters: BTreeSet<BTreeSet<String>> = graph
            .clusters()
            .into_iter()
            .map(|cluster| cluster.into_iter().collect())
            .collect();
        assert_eq!(
            actual_clusters, expected_clusters,
            "graph #{graph_index} n={n} edges={edges:?}: clusters differ"
        );

        let baseline = distinct(&labels);
        let mut expected_bridges: BTreeSet<(String, String)> = BTreeSet::new();
        for (i, &(a, b)) in edges.iter().enumerate() {
            if a == b {
                continue;
            }
            if distinct(&components(n, &edges, Some(i))) > baseline {
                let (x, y) = (names[a].clone(), names[b].clone());
                expected_bridges.insert(if x <= y { (x, y) } else { (y, x) });
            }
        }
        let actual_bridges: BTreeSet<(String, String)> = graph
            .bridges()
            .into_iter()
            .map(|(x, y)| if x <= y { (x, y) } else { (y, x) })
            .collect();
        assert_eq!(
            actual_bridges, expected_bridges,
            "graph #{graph_index} n={n} edges={edges:?}: bridges differ"
        );
    }
}
