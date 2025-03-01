package com.upc.gessi.qrapids.app.domain.controllers;

import com.upc.gessi.qrapids.app.domain.adapters.AssessQF;
import com.upc.gessi.qrapids.app.domain.adapters.Forecast;
import com.upc.gessi.qrapids.app.domain.adapters.QMA.QMAQualityFactors;
import com.upc.gessi.qrapids.app.domain.adapters.QMA.QMARelations;
import com.upc.gessi.qrapids.app.domain.adapters.QMA.QMASimulation;
import com.upc.gessi.qrapids.app.domain.exceptions.*;
import com.upc.gessi.qrapids.app.domain.models.*;
import com.upc.gessi.qrapids.app.domain.models.Factor;
import com.upc.gessi.qrapids.app.domain.repositories.Profile.ProfileProjectStrategicIndicatorsRepository;
import com.upc.gessi.qrapids.app.domain.repositories.QFCategory.QFCategoryRepository;
import com.upc.gessi.qrapids.app.domain.repositories.QualityFactor.QualityFactorMetricsRepository;
import com.upc.gessi.qrapids.app.domain.repositories.QualityFactor.QualityFactorRepository;
import com.upc.gessi.qrapids.app.domain.repositories.StrategicIndicator.StrategicIndicatorQualityFactorsRepository;
import com.upc.gessi.qrapids.app.presentation.rest.dto.*;
import com.upc.gessi.qrapids.app.presentation.rest.services.helpers.Messages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;

import static java.time.temporal.ChronoUnit.DAYS;

@Service
public class FactorsController {

    @Autowired
    private QMARelations qmaRelations;

    @Autowired
    private AssessQF assessQF;

    @Autowired
    private QualityFactorRepository qualityFactorRepository;

    @Autowired
    private QualityFactorMetricsRepository qualityFactorMetricsRepository;

    @Autowired
    private StrategicIndicatorQualityFactorsRepository strategicIndicatorQualityFactorsRepository;

    @Autowired
    private ProfileProjectStrategicIndicatorsRepository profileProjectStrategicIndicatorsRepository;

    @Autowired
    private AlertsController alertsController;

    @Autowired
    private MetricsController metricsController;

    @Autowired
    private ProjectsController projectsController;

    @Autowired
    private ProfilesController profilesController;

    @Autowired
    private QualityFactorMetricsController qualityFactorMetricsController;

    // it was made to use these variables in static method
    @Autowired
    private QFCategoryRepository factorCategoryRepository;
    @Autowired
    private QMASimulation qmaSimulation;
    @Autowired
    private  Forecast qmaForecast;
    @Autowired
    private  QMAQualityFactors qmaQualityFactors;

    private Logger logger = LoggerFactory.getLogger(StrategicIndicatorsController.class);

    //Old getFactorCategories
    /*public List<QFCategory> getFactorCategories () {
        List<QFCategory> factorCategoriesList = new ArrayList<>();
        Iterable<QFCategory> factorCategoriesIterable = factorCategoryRepository.findAll();
        factorCategoriesIterable.forEach(factorCategoriesList::add);
        return factorCategoriesList;
    }*/

    public List<QFCategory> getFactorCategories (String name) {
        List<QFCategory> factorCategoryList = new ArrayList<>();
        Iterable<QFCategory> factorCategoryIterable;
        if (name != null) factorCategoryIterable = factorCategoryRepository.findAllByName(name);
        else factorCategoryIterable = factorCategoryRepository.findAll();
        factorCategoryIterable.forEach(factorCategoryList::add);
        return factorCategoryList;
    }
    //Old getFactorCategories
   /*public void getFactorCategories(List<Map<String, String>> categories) throws CategoriesException {
        if (categories.size() > 1) {
            factorCategoryRepository.deleteAll();
            for (Map<String, String> c : categories) {
                QFCategory sic = new QFCategory();
                sic.setName(c.get("name"));
                sic.setColor(c.get("color"));
                Float upperThreshold = Float.valueOf(c.get("upperThreshold"));
                sic.setUpperThreshold(upperThreshold / 100f);
                factorCategoryRepository.save(sic);
            }
        } else {
            throw new CategoriesException();
        }
    }*/

    // new functions
    public static String buildDescriptiveLabelAndValue(Pair<Float, String> value) {
        String labelAndValue;

        String numeric_value = String.format(Locale.ENGLISH, "%.2f", value.getFirst());

        if (value.getSecond().isEmpty())
            labelAndValue = numeric_value;
        else{
            labelAndValue = value.getSecond();
            if (!numeric_value.isEmpty())
                labelAndValue += " (" + numeric_value + ')';
        }

        return labelAndValue;
    }

    public List<String> getAllNames() {
        //If name doesnt exists returns true
        Iterable<QFCategory> categories = factorCategoryRepository.findAll();
        List<String> names = new ArrayList<String>();
        for(QFCategory qf : categories)  {
            if(!names.contains(qf.getName())) names.add(qf.getName());
        }
        return names;

    }

    public void deleteFactorCategory(String name) {

        Iterable<QFCategory> factorCategoryIterable = factorCategoryRepository.findAllByName(name);
        for(QFCategory m : factorCategoryIterable)  {
            factorCategoryRepository.deleteById(m.getId());
        }

    }

    public void updateFactorCategory(List<Map<String, String>> categories ,String name) throws CategoriesException {

        if(checkIfCategoriesHasRepeats(categories)) throw new CategoriesException(Messages.CATEGORIES_HAVE_REPEATS);
        deleteFactorCategory(name);
        newFactorCategories(categories, name);
    }

    public boolean CheckIfNameExists(String name) {
        //If name doesnt exists returns true
        return factorCategoryRepository.existsByName(name);
    }

    public boolean checkIfCategoriesHasRepeats(List<Map<String, String>> categories) {
        List<String> repeated = new ArrayList<>();
        for (Map<String, String> c : categories) {
            if (repeated.contains(c.get("type"))) {
                return true;
            }
            repeated.add(c.get("type"));
        }
        return false;
    }

    public void newFactorCategories (List<Map<String, String>> categories, String name) throws CategoriesException {

        boolean exists=CheckIfNameExists(name);
        if(exists) throw new CategoriesException(Messages.CATEGORY_ALREADY_EXISTS);

        if(checkIfCategoriesHasRepeats(categories)) throw new CategoriesException(Messages.CATEGORIES_HAVE_REPEATS);

        if (categories.size() > 2) {
            //metricCategoryRepository.deleteAll();
            for (Map<String, String> c : categories) {
                QFCategory qfCategory = new QFCategory();
                qfCategory.setName(name);
                qfCategory.setType(c.get("type"));
                qfCategory.setColor(c.get("color"));
                float upperThreshold = Float.parseFloat(c.get("upperThreshold"));
                qfCategory.setUpperThreshold(upperThreshold/100f);
                factorCategoryRepository.save(qfCategory);
            }
        } else {
            throw new CategoriesException(Messages.NOT_ENOUGH_CATEGORIES);
        }
    }

    public Factor findFactorByExternalIdAndProjectId(String externalId, Long prjId) throws QualityFactorNotFoundException {
        Factor factor = qualityFactorRepository.findByExternalIdAndProjectId(externalId,prjId);
        if (factor == null) {
            throw new QualityFactorNotFoundException(externalId);
        }
        return factor;
    }

    public void importFactorsAndUpdateDatabase() throws IOException, CategoriesException, ProjectNotFoundException, MetricNotFoundException {
        List<String> projects = projectsController.getAllProjectsExternalID();
        for (String prj : projects) {
            List<DTOFactorEvaluation> factors = getAllFactorsEvaluation(prj, null,false);
            // when we import factors we don't use profile and don't filter by Data Base
            List<DTODetailedFactorEvaluation> factorsWithMetrics = getAllFactorsWithMetricsCurrentEvaluation(prj, null,false);
            updateDataBaseWithNewFactors(prj, factors, factorsWithMetrics);
        }
    }

    public void updateDataBaseWithNewFactors (String prjExternalID,List<DTOFactorEvaluation> factors, List<DTODetailedFactorEvaluation> factorsWithMetrics) throws ProjectNotFoundException, MetricNotFoundException {
        Project project = projectsController.findProjectByExternalId(prjExternalID);
        for (DTOFactorEvaluation factor : factors) {
            Factor factorsSaved = qualityFactorRepository.findByExternalIdAndProjectId(factor.getId(),project.getId());
            if (factorsSaved == null) {
                // ToDo factor composition with corresponding metrics weights (default all metrics are not weighted)
                List<String> qualityMetrics = new ArrayList<>();
                int cont = 0;
                boolean found = false;
                while (cont < factorsWithMetrics.size() && !found){
                    DTODetailedFactorEvaluation df = factorsWithMetrics.get(cont);
                    if (df.getId().equals(factor.getId())) {
                        found = true;
                        for (DTOMetricEvaluation m : df.getMetrics()) {
                            Metric metric = metricsController.findMetricByExternalIdAndProjectId(m.getId(), project.getId());
                            qualityMetrics.add(String.valueOf(metric.getId()));
                            qualityMetrics.add(String.valueOf(-1l));
                        }
                    }
                    cont += 1;
                }
                Factor newFactor = saveImportedQualityFactor(factor.getId(),factor.getName(),factor.getDescription(),qualityMetrics,project);
                qualityFactorRepository.save(newFactor);
            }
        }
    }

    private Factor saveImportedQualityFactor(String id, String name, String description, List<String> qualityMetrics, Project project) throws MetricNotFoundException {
        Factor qualityFactor;
        // create Quality Factor minim (without quality factors and weighted)
        qualityFactor = new Factor (id, name, description, project);
        qualityFactor.setCategoryName("Default");
        qualityFactorRepository.save(qualityFactor);
        boolean weighted = assignQualityMetricsToQualityFactor (qualityMetrics, qualityFactor);
        qualityFactor.setWeighted(weighted);
        qualityFactorRepository.save(qualityFactor);
        return qualityFactor;
    }

    public List<Factor> getQualityFactorsByProject (Project project) {
        return qualityFactorRepository.findByProject_IdOrderByName(project.getId());
    }

    public Factor getQualityFactorById (Long qualityFactorId) throws QualityFactorNotFoundException {
        Optional<Factor> qualityFactorOptional = qualityFactorRepository.findById(qualityFactorId);
        if (qualityFactorOptional.isPresent()) {
            return qualityFactorOptional.get();
        } else {
            throw new QualityFactorNotFoundException(qualityFactorId.toString());
        }
    }
    public Factor getQualityFactorByExternalId (String qualityFactorExternalId) throws QualityFactorNotFoundException {
        Optional<Factor> qualityFactorOptional = qualityFactorRepository.findByExternalId(qualityFactorExternalId);
        if (qualityFactorOptional.isPresent()) {
            return qualityFactorOptional.get();
        } else {
            throw new QualityFactorNotFoundException(qualityFactorExternalId);
        }
    }

    public Factor getQualityFactorByExternalIdAndProjectId (String qualityFactorExternalId, Long projectId) throws QualityFactorNotFoundException {
        Optional<Factor> qualityFactorOptional = qualityFactorRepository.findByExternalIdAndProject_Id(qualityFactorExternalId, projectId);
        if (qualityFactorOptional.isPresent()) {
            return qualityFactorOptional.get();
        } else {
            throw new QualityFactorNotFoundException(qualityFactorExternalId);
        }
    }

    public Factor saveQualityFactorWithCategory(String name, String description, String threshold, List<String> qualityMetrics, String type, String category, Project project) throws MetricNotFoundException {
        Factor qualityFactor;
        // create Quality Factor minim (without quality factors and weighted)
        qualityFactor = new Factor (name, description, project, type, category);
        if (!threshold.isEmpty()) // check if threshold is specified and then set it
            qualityFactor.setThreshold(Float.parseFloat(threshold));
        else
            qualityFactor.setThreshold(null);
        qualityFactor.setCategoryName(category);
        qualityFactorRepository.save(qualityFactor);
        boolean weighted = assignQualityMetricsToQualityFactor (qualityMetrics, qualityFactor);
        qualityFactor.setWeighted(weighted);
        qualityFactorRepository.save(qualityFactor);
        return qualityFactor;
    }

    private boolean assignQualityMetricsToQualityFactor (List<String> qualityMetrics, Factor qualityFactor) throws MetricNotFoundException {
        List<QualityFactorMetrics> qualityMetricsWeights = new ArrayList();
        boolean weighted = false;
        String metricId;
        Float weight;
        // generate QualityFactorMetrics class objects from List<String> qualityMetrics
        while (!qualityMetrics.isEmpty()) {
            QualityFactorMetrics qfm;
            metricId = qualityMetrics.get(0);
            Metric metric = metricsController.getMetricById(Long.parseLong(metricId));
            weight = Float.parseFloat(qualityMetrics.get(1));
            if (weight == -1) {
                qfm = qualityFactorMetricsController.saveQualityFactorMetric(weight, metric, qualityFactor);
                weighted = false;
            } else {
                qfm = qualityFactorMetricsController.saveQualityFactorMetric(weight, metric, qualityFactor);
                weighted = true;
            }
            qualityMetricsWeights.add(qfm);
            qualityMetrics.remove(1);
            qualityMetrics.remove(0);
        }
        // create the association between Quality Factor and its Metrics
        qualityFactor.setQualityFactorMetricsList(qualityMetricsWeights);
        return weighted;
    }

    public Factor editQualityFactor(Long factorId, String name, String description, String threshold, List<String> qualityMetrics, String type) throws QualityFactorNotFoundException, QualityFactorMetricsNotFoundException, MetricNotFoundException {
        Factor factor = getQualityFactorById(factorId);
        factor.setName(name);
        factor.setDescription(description);
        factor.setType(type);
        if (!threshold.isEmpty()) // check if threshold is specified and then set it
            factor.setThreshold(Float.parseFloat(threshold));
        else
            factor.setThreshold(null);
        // Actualize Quality Metrics
        boolean weighted = reassignQualityMetricsToQualityFactor (qualityMetrics, factor);
        factor.setWeighted(weighted);
        qualityFactorRepository.save(factor);
        return  factor;
    }

    public Factor editQualityFactorWithCategory(Long factorId, String name, String description, String threshold, List<String> qualityMetrics, String type, String category) throws QualityFactorNotFoundException, QualityFactorMetricsNotFoundException, MetricNotFoundException {
        Factor factor = getQualityFactorById(factorId);
        factor.setName(name);
        factor.setDescription(description);
        factor.setCategoryName(category);
        factor.setType(type);
        if (!threshold.isEmpty()) // check if threshold is specified and then set it
            factor.setThreshold(Float.parseFloat(threshold));
        else
            factor.setThreshold(null);
        // Actualize Quality Metrics
        boolean weighted = reassignQualityMetricsToQualityFactor (qualityMetrics, factor);
        factor.setWeighted(weighted);
        qualityFactorRepository.save(factor);
        return  factor;
    }

    private  boolean reassignQualityMetricsToQualityFactor (List<String> qualityMetrics, Factor factor) throws QualityFactorMetricsNotFoundException, MetricNotFoundException {
        List<QualityFactorMetrics> newQualityFactorsWeights = new ArrayList();
        // Delete oldQualityMetricsWeights
        List<QualityFactorMetrics> oldQualityMetricsWeights = qualityFactorMetricsRepository.findByFactor(factor);
        factor.setQualityFactorMetricsList(null);
        for (QualityFactorMetrics old : oldQualityMetricsWeights) {
            qualityFactorMetricsController.deleteQualityFactorMetric(old.getId());
        }
        boolean weighted = false;
        String metricId;
        Float weight;
        // generate QualityFactorMetrics class objects from List<String> qualityMetrics
        while (!qualityMetrics.isEmpty()) {
            QualityFactorMetrics qfm;
            metricId = qualityMetrics.get(0);
            Metric metric = metricsController.getMetricById(Long.parseLong(metricId));
            weight = Float.parseFloat(qualityMetrics.get(1));
            if (weight == -1) {
                qfm = qualityFactorMetricsController.saveQualityFactorMetric(weight, metric, factor);
                weighted = false;
            } else {
                qfm = qualityFactorMetricsController.saveQualityFactorMetric(weight, metric, factor);
                weighted = true;
            }
            newQualityFactorsWeights.add(qfm);
            qualityMetrics.remove(1);
            qualityMetrics.remove(0);
        }
        // create the association between Strategic Indicator and its Quality Factors
        factor.setQualityFactorMetricsList(newQualityFactorsWeights);
        return weighted;
    }

    public void deleteFactor(Long id) throws QualityFactorNotFoundException, DeleteFactorException {
        if(qualityFactorRepository.existsById(id)){
            Optional<Factor> factor = qualityFactorRepository.findById(id);
            if (strategicIndicatorQualityFactorsRepository.findByQuality_factor(factor.get()).size() == 0) {
                qualityFactorRepository.deleteById(id);
            } else {
                throw new DeleteFactorException();
            }
        } else {
            throw new QualityFactorNotFoundException(id.toString());
        }
    }

    public boolean assessQualityFactors(String projectExternalId, LocalDate dateFrom) throws IOException, CategoriesException, ProjectNotFoundException {
        boolean correct = true;
        if (dateFrom != null) {
            LocalDate dateTo = new Date().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
            while (correct && dateFrom.compareTo(dateTo) <= 0) {
                correct = assessDateQualityFactors(projectExternalId, dateFrom);
                dateFrom = dateFrom.plusDays(1);
            }
        } else {
            correct = assessDateQualityFactors(projectExternalId, null);
        }
        return correct;
    }

    private boolean assessDateQualityFactors(String projectExternalId, LocalDate dateFrom) throws IOException, CategoriesException, ProjectNotFoundException {
        boolean correct = true;

        // if there is no specific project as a parameter, all the projects are assessed
        if (projectExternalId == null) {
            List<String> projects = projectsController.getAllProjectsExternalID();
            int i=0;
            while (i<projects.size() && correct) {
                qmaQualityFactors.prepareQFIndex(projects.get(i));
                correct = assessDateProjectQualityFactors(projects.get(i), dateFrom);
                i++;
            }
        }
        else {
            qmaQualityFactors.prepareQFIndex(projectExternalId);
            correct = assessDateProjectQualityFactors(projectExternalId, dateFrom);
        }
        return correct;
    }

    private boolean assessDateProjectQualityFactors(String project, LocalDate evaluationDate) throws IOException, ProjectNotFoundException {
        //metrics list, each of them includes list of QF in which is involved
        MetricEvaluation metricEvaluationQma = new MetricEvaluation();
        List<DTOMetricEvaluation> metricList;

        // If we receive an evaluationData is because we are recomputing historical data.
        // We need the metrics for an specific day, not the last evaluation
        if (evaluationDate == null) {
            evaluationDate = new Date().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
            metricList = metricsController.getAllMetricsCurrentEvaluation(project, null);
        }
        else {
            metricList = metricsController.getAllMetricsHistoricalEvaluation(project, null, evaluationDate, evaluationDate);
            // when there is no historic metrics values for specified day --> take the last assessment
            if (metricList.size() == 0) metricList = metricsController.getAllMetricsCurrentEvaluation(project, null);
        }
        metricEvaluationQma.setMetrics(metricList);

        Project proj = projectsController.findProjectByExternalId(project);

        // CHECK METRICS ALERTS
        LocalDate today = LocalDate.now();
        if(evaluationDate.equals(today)) {
            for (DTOMetricEvaluation m : metricList) {
                alertsController.shouldCreateMetricAlert(m, m.getValue(), proj.getId());
            }
        }

        return assessProjectQualityFactors(evaluationDate, project, metricEvaluationQma);
    }

    private boolean assessProjectQualityFactors(LocalDate evaluationDate, String  projectExternalId, MetricEvaluation metricEvaluationQMA) throws IOException {
        // List of ALL the quality factors in the local database
        Project project = new Project();
        try {
            project = projectsController.findProjectByExternalId(projectExternalId);
        } catch (ProjectNotFoundException e) {
            List <String> prj = Arrays.asList(projectExternalId);
            projectsController.updateDataBaseWithNewProjects(prj);
        }
        Iterable<Factor> factorIterable = qualityFactorRepository.findByProject_Id(project.getId());

        boolean correct = true;

        // 1.- We need to remove old data from metric evaluations in the quality_factor relationship attribute
        //metricEvaluationQMA.clearQualityFactorsRelations(evaluationDate);

        // 2.- We will compute the evaluation values for the QFs, adding the corresponding relations to the metrics
        //      used for these computation
        for (Factor f : factorIterable) {
            metricEvaluationQMA.clearQualityFactorsRelations(f.getExternalId());
            correct = assessQualityFactor(evaluationDate, projectExternalId, f, metricEvaluationQMA);
        }

        // 3. When all the quality factors is calculated, we need to update the metrics with the information of
        // the quality factors using them
        metricsController.setMetricQualityFactorRelation(metricEvaluationQMA.getMetrics(), projectExternalId);
        return correct;
    }

    private boolean assessQualityFactor(LocalDate evaluationDate, String project, Factor qualityFactor, MetricEvaluation metricEvaluationQMA) throws IOException {
        boolean correct = true;
        // We need the evaluation for the metrics used to compute "qf"
        List<Float> listMetricsAssessmentValues = new ArrayList<>();
        // List of metrics impacting in ONE quality factor
        List<String> qfMetrics;
        List<DTOMetricEvaluation> metricList = new ArrayList<>();
        List<String> missingMetrics = new ArrayList<>(); //List of metrics without assessment ---> QF assessment incomplete
        long metricsMismatch=0;

        // We need to identify the metrics in metrics_qma that are used to compute QF
        Map<String,String> mapQFMetrics = new HashMap<>();
        qfMetrics = qualityFactor.getMetrics(); // list of metrics external ids
        metricsMismatch = buildMetricsInfoAndCalculateMismatch(evaluationDate, project, qualityFactor, metricEvaluationQMA, listMetricsAssessmentValues, qfMetrics, metricList, missingMetrics, metricsMismatch, mapQFMetrics);

        String assessmentValueOrLabel = "";
        try {
            assessmentValueOrLabel = assessQualityFactors(evaluationDate, project, qualityFactor, listMetricsAssessmentValues, qfMetrics, missingMetrics, metricsMismatch, assessmentValueOrLabel);
        } catch (AssessmentErrorException | CategoriesException e) {
            logger.error(e.getMessage(), e);
            correct = false;
        }

        // Save relations of metric -> QF
        if (correct && !assessmentValueOrLabel.isEmpty()) {
            correct = buildAndSaveMetricQFRelation(evaluationDate, project, qualityFactor, metricList, assessmentValueOrLabel);
        }

        return correct;
    }

    private long buildMetricsInfoAndCalculateMismatch(LocalDate evaluationDate, String project, Factor qualityFactor, MetricEvaluation metricEvaluationQMA, List<Float> listMetricsAssessmentValues, List<String> qfMetrics, List<DTOMetricEvaluation> metricList, List<String> missingMetrics, long metricsMismatch, Map<String, String> mapQFMetrics) throws IOException {
        int index;
        boolean metricFound;
        DTOMetricEvaluation metric;//qfMetrics is the list of metrics that are needed to compute the QF
        //missingMetrics will contain the metrics not found in QMA
        for (String mID : qfMetrics) {
            // mID contains a metric that is used to compute the QF
            // We need to find the assessment of the metric in the QF definition, in case the metric is missing
            // this metric will be added to the missing metrics list
            index =0;
            metricFound = false;
            while (!metricFound && index < metricEvaluationQMA.getMetrics().size()){
                metric = metricEvaluationQMA.getMetrics().get(index++);
                if (metric.getId().equals(mID)) {
                    metricFound = true;
                    metricList.add(metric);
                    listMetricsAssessmentValues.add(metric.getValue());
                    mapQFMetrics.put(metric.getId(), metricsController.getMetricLabelFromValue(metric.getValue()));
                    // ToDo using getHardID or not
                    metric.addQualityFactors(qualityFactor.getExternalId());
                    //metric.addQualityFactors(evaluation.Factor.getHardID("", qualityFactor.getExternalId(), evaluationDate));
                    // If there is some missing days, we keep the maximum gap to be materialised
                    long mismach = DAYS.between(metric.getDate(), evaluationDate);
                    if (mismach > metricsMismatch)
                        metricsMismatch=mismach;
                }
            }
            // mID is the metric searched in QMA results
            if (!metricFound)
                missingMetrics.add(mID);
        }
        return metricsMismatch;
    }

    private boolean buildAndSaveMetricQFRelation(LocalDate evaluationDate, String project, Factor qualityFactor, List<DTOMetricEvaluation> metricList, String assessmentValueOrLabel) throws IOException {
        boolean correct;
        List<String> metricsIds = new ArrayList<>();
        List<Float> weights = new ArrayList<>();
        List<Float> values = new ArrayList<>();
        List<String> labels = new ArrayList<>();
        for (DTOMetricEvaluation dtoMetricEvaluation : metricList) {
            metricsIds.add(dtoMetricEvaluation.getId());
            Float weight = -1f; // default value --> no weighted factor
            // when QF is not weighted the weight of metric value is computed as average
            if (!qualityFactor.isWeighted()) {
                weight = 1f/metricList.size();
            } else { // when QF is weighted the weight of metric has corresponding value
                List<String> mw = qualityFactor.getWeightsWithExternalId();
                weight = Float.parseFloat(mw.get(mw.indexOf(dtoMetricEvaluation.getId()) + 1)) / 100;
            }
            // save weights of metrics
            weights.add(weight);

            if (weight == -1f){
                values.add(dtoMetricEvaluation.getValue()*1f/metricList.size()); // value for representation (average)
            } else {
                values.add(dtoMetricEvaluation.getValue() * weight); // value of weighted metric
            }
            labels.add(metricsController.getMetricLabelFromValue(dtoMetricEvaluation.getValue()));
        }
        correct = saveMetricQFRelation(project, metricsIds, qualityFactor.getExternalId(), evaluationDate, weights, values, labels, assessmentValueOrLabel);
        return correct;
    }

    private boolean saveMetricQFRelation(String prj, List<String> metricsIds, String qf, LocalDate evaluationDate, List<Float> weights, List<Float> metricValues, List<String> metricsLabels, String qfValueOrLabel) throws IOException {
        return qmaRelations.setQualityFactorMetricRelation(prj, metricsIds, qf, evaluationDate, weights, metricValues, metricsLabels, qfValueOrLabel);
    }

    private String assessQualityFactors(LocalDate evaluationDate, String project, Factor qualityFactor, List<Float> listMetricsAssessmentValues, List<String> qfMetrics, List<String> missingMetrics, long metricsMismatch, String assessmentValueOrLabel) throws IOException, AssessmentErrorException, CategoriesException {
        if (!listMetricsAssessmentValues.isEmpty()) {
            float value;
            List<Float> weights = new ArrayList<>();
            boolean weighted = qualityFactor.isWeighted();
            if (weighted) {
                List<String> metricsWeights = qualityFactor.getWeights();
                for ( int i = 1; i < metricsWeights.size(); i+=2) {
                    weights.add(Float.valueOf(metricsWeights.get(i)));
                }
                value = assessQF.assessQF_weighted(listMetricsAssessmentValues, weights);
            } else {
                value = assessQF.assessQF(listMetricsAssessmentValues, qfMetrics.size());
            }
            assessmentValueOrLabel = String.valueOf(value);
            String info = "metrics: {";
            for (int j = 0; j < listMetricsAssessmentValues.size(); j++) {
                String metricInfo = " " + qfMetrics.get(j) + " (value: " +  listMetricsAssessmentValues.get(j) + ", ";
                if (weighted) metricInfo += "weight: " + weights.get(j).intValue() + "%);";
                else metricInfo += "no weighted);";
                info += metricInfo;
            }
            if (weighted) {
                info += " }, formula: weighted average, value: " + value + ", category: " + qualityFactor.getCategoryName();
            } else {
                info += " }, formula: average, value: " + value + ", category: " + qualityFactor.getCategoryName();
            }
            // saving the QF's assessment
            // in case of new factor -> indicators list is empty
            List<String> indicators = new ArrayList<>();
            // in case of edit factor -> old indicators list is specified
            for (StrategicIndicatorQualityFactors siqf : strategicIndicatorQualityFactorsRepository.findByQuality_factor(qualityFactor)) {
                //DTOStrategicIndicatorEvaluation si = strategicIndicatorsController.getSingleStrategicIndicatorsCurrentEvaluation(siqf.getStrategic_indicator().getExternalId(), project);
                //indicators.add(StrategicIndicator.getHardID(project, si.getId(), si.getDate()));
                indicators.add(siqf.getStrategic_indicator().getExternalId());
            }
            if (!qmaQualityFactors.setQualityFactorValue(
                    project,
                    qualityFactor.getExternalId(),
                    qualityFactor.getName(),
                    qualityFactor.getDescription(),
                    value,
                    info,
                    evaluationDate,
                    null,
                    missingMetrics,
                    metricsMismatch,
                    indicators
            ))
                throw new AssessmentErrorException();
            // CHECK FACTORS ALERTS
            LocalDate today = LocalDate.now();
            if(evaluationDate.equals(today)) alertsController.shouldCreateFactorAlert(qualityFactor,value);
        }
        return assessmentValueOrLabel;
    }

    // Function for AssessQualityFactor to concrete project
    public boolean assessQualityFactor(String name, String prj) throws IOException, ProjectNotFoundException {
        boolean correct = false;
        // Local date to be used as evaluation date
        Date input = new Date();
        LocalDate evaluationDate = input.toInstant().atZone(ZoneId.systemDefault()).toLocalDate();

        // Strategic Indicator
        Project project = projectsController.findProjectByExternalId(prj);
        Factor qf = qualityFactorRepository.findByNameAndProject_Id(name, project.getId());

        // All the metrics' assessment from QMA external service
        MetricEvaluation metricEvaluationQma = new MetricEvaluation();

        // We will compute the evaluation values for the QF for THIS CONCRETE component
        // 1.- We need to remove old data from metric evaluations in the quality_factors relationship attribute
        metricEvaluationQma.setMetrics(metricsController.getAllMetricsEvaluation(prj, null));
        metricEvaluationQma.clearQualityFactorsRelations(qf.getExternalId());
        //metricEvaluationQma.clearQualityFactorsRelations(evaluationDate, qf.getExternalId());

        correct = assessQualityFactor(evaluationDate, prj, qf, metricEvaluationQma);

        // 3. When all the quality factors is calculated, we need to update the metrics with the information of
        // the quality factors using them
        metricsController.setMetricQualityFactorRelation(metricEvaluationQma.getMetrics(), prj);

        return correct;
    }

    public DTOFactorEvaluation getSingleFactorEvaluation(String factorId, String projectExternalId) throws IOException {
        return qmaQualityFactors.SingleCurrentEvaluation(factorId, projectExternalId);
    }

    public List<DTOFactorEvaluation> getAllFactorsEvaluation(String projectExternalId, String profile, boolean filterDB) throws IOException {
        return qmaQualityFactors.getAllFactors(projectExternalId, profile, filterDB);
    }

    public List<DTODetailedFactorEvaluation> getAllFactorsWithMetricsCurrentEvaluation(String projectExternalId, String profile, boolean filterDB) throws IOException, ProjectNotFoundException {
        return qmaQualityFactors.CurrentEvaluation(null, projectExternalId, profile, filterDB);
    }

    public List<DTODetailedFactorEvaluation> getFactorsWithMetricsForOneStrategicIndicatorCurrentEvaluation(String strategicIndicatorId, String projectExternalId) throws IOException, ProjectNotFoundException {
        // we are looking for factors of one SI -> profile is already checked by SI Controller & we need to filterDB (if factor is involved in SI, it can't be deleted)
        return qmaQualityFactors.CurrentEvaluation(strategicIndicatorId, projectExternalId, null, true);
    }

    public List<DTOFactorEvaluation> getAllFactorsHistoricalEvaluation (String projectExternalId, String profile, LocalDate dateFrom, LocalDate dateTo) throws IOException {
        return qmaQualityFactors.getAllFactorsHistoricalData(projectExternalId, profile, dateFrom, dateTo);
    }

    public List<DTODetailedFactorEvaluation> getAllFactorsWithMetricsHistoricalEvaluation(String projectExternalId, String profile, LocalDate dateFrom, LocalDate dateTo) throws IOException, ProjectNotFoundException {
        return qmaQualityFactors.HistoricalData(null, dateFrom, dateTo, projectExternalId, profile);
    }

    public List<DTODetailedFactorEvaluation> getFactorsWithMetricsForOneStrategicIndicatorHistoricalEvaluation(String strategicIndicatorId, String projectExternalId, LocalDate dateFrom, LocalDate dateTo) throws IOException, ProjectNotFoundException {
        // we are looking for factors of one SI -> profile is already checked by SI Controller
        return qmaQualityFactors.HistoricalData(strategicIndicatorId, dateFrom, dateTo, projectExternalId, null);
    }

    public List<DTODetailedFactorEvaluation> getFactorsWithMetricsPrediction(List<DTODetailedFactorEvaluation> currentEvaluation, String technique, String freq, String horizon, String projectExternalId) throws IOException, MetricNotFoundException, QualityFactorNotFoundException, StrategicIndicatorNotFoundException {
        //Save the current evaluations metrics dto as they are going to be changed for the forecast creation
        Map<String,DTOMetricEvaluation> currentMetricEvals = new HashMap<>();
        for (int f = 0; f < currentEvaluation.size(); ++f){
            for (int m = 0; m < currentEvaluation.get(f).getMetrics().size(); ++m){
                currentMetricEvals.put(currentEvaluation.get(f).getId()+currentEvaluation.get(f).getMetrics().get(m).getId(),currentEvaluation.get(f).getMetrics().get(m));
            }
        }
        List<DTODetailedFactorEvaluation> forecast = qmaForecast.ForecastDetailedFactor(currentEvaluation, technique, freq, horizon, projectExternalId);
        int period=Integer.parseInt(horizon);
        for (int qf=0; qf < forecast.size(); ++qf){
            String factorId = forecast.get(qf).getId();
            List <DTOMetricEvaluation> qfMetricsPredictions = forecast.get(qf).getMetrics();
            int j = 0;
            for(int i = 0; i < qfMetricsPredictions.size(); i += period, ++j){
                while (i < qfMetricsPredictions.size() && qfMetricsPredictions.get(i).getValue() == null) {
                    ++i; ++j;
                }
                if(i >= qfMetricsPredictions.size()) break;
                int subListEnd = Math.min(i + period, forecast.size());
                List<DTOMetricEvaluation> forecastedValues = new ArrayList<>(qfMetricsPredictions.subList(i, subListEnd));
                String metricId = forecastedValues.get(0).getId();
                DTOMetricEvaluation currentMetricEval = currentMetricEvals.get(factorId+metricId);
                alertsController.checkAlertsForMetricsPrediction(currentMetricEval, forecastedValues, projectExternalId, technique);
            }
        }

        return forecast;
    }

    public List<DTOFactorEvaluation> simulate (Map<String, Float> metricsValue, String projectExternalId, String profile, LocalDate date) throws IOException {
        return qmaSimulation.simulateQualityFactors(metricsValue, projectExternalId, profile, date);
    }

    public void setFactorStrategicIndicatorRelation (List<DTOFactorEvaluation> factorList, String projectExternalId) throws IOException {
        qmaQualityFactors.setFactorStrategicIndicatorRelation(factorList, projectExternalId);
    }

    public String getFactorLabelFromValue (Float f) {
        List <QFCategory> qfCategoryList = factorCategoryRepository.findAllByOrderByUpperThresholdAsc();
        if (f != null) {
            for (QFCategory qfCategory : qfCategoryList) {
                if (f <= qfCategory.getUpperThreshold())
                    return qfCategory.getType();
            }
        }
        return "No Category";
    }

    public String getFactorLabelFromNameAndValue (String nameCategory, Float val_metric) {
        List <QFCategory> qfCategoryList = factorCategoryRepository.findAllByOrderByUpperThresholdAsc();
        //List <QFCategory> qfCategoryList = factorCategoryRepository.findAllByName(nameCategory); TODO: no funciona por lo que he cambiado la implementacion
        Float distance = 1.1f;  //distancia demasiado grande, para que se recalcule
        String type = "No Category";
        for (QFCategory qfCategory : qfCategoryList) {
            System.out.println(qfCategory.getType() + " " + qfCategory.getName() + " " + qfCategory.getUpperThreshold() + " "+ distance);
            System.out.println(qfCategory.getUpperThreshold()-val_metric);
            if (val_metric <= qfCategory.getUpperThreshold() &&     //si la metrica puede ser de ese thresh
                    distance>(qfCategory.getUpperThreshold()-val_metric) // y la distancia hasta ahora es MAYOR a la nueva
                    && qfCategory.getName().equals(nameCategory)){      //y la categoria es la correcta
                distance = qfCategory.getUpperThreshold()-val_metric;
                type = qfCategory.getType();
            }

        }
        if (type == "No Category") type = nameCategory;
        return type;
    }

    public String getCategoryFromRationale (String rationale){
        String category = rationale.substring(rationale.indexOf("category") +  10, rationale.length());  //+9 porque te da el indice de c: hay que sumarle toda la palabra y el espacio
        return category;
    }

    public List<DTOFactorEvaluation> getFactorsPrediction(List<DTOFactorEvaluation> currentEvaluation, String prj, String technique, String freq, String horizon) throws IOException, MetricNotFoundException, QualityFactorNotFoundException, StrategicIndicatorNotFoundException {
        List<DTOFactorEvaluation> forecast = qmaForecast.ForecastFactor(currentEvaluation, technique, freq, horizon, prj);
        int period=Integer.parseInt(horizon);
        int j=0;
        for(int i=0; i < forecast.size(); i+=period, ++j){
            while (i < forecast.size() && forecast.get(i).getValue() == null){
                ++i;
                ++j;
            }
            if (i>=forecast.size()) break;
            int subListEnd = Math.min(i + period, forecast.size());
            List<DTOFactorEvaluation> forecastedValues = new ArrayList<>(forecast.subList(i, subListEnd));
            List<Float> predictedValues = new ArrayList<>();
            List<Date> predictionDates = new ArrayList<>();
            for (int f=0 ;f<forecastedValues.size();++f){
                predictedValues.add(forecastedValues.get(f).getValue().getFirst());
                LocalDate predictedDate = forecastedValues.get(f).getDate();
                Date date;
                if (predictedDate==null) date = null;
                else date = java.sql.Date.valueOf(predictedDate);
                predictionDates.add(date);
            }
            alertsController.checkAlertsForFactorsPrediction(currentEvaluation.get(j).getValue().getFirst(),currentEvaluation.get(j).getId(), predictedValues, predictionDates, prj, technique);
        }
        return forecast;
    }

    public List<Factor> getQualityFactorsByProjectAndProfile(String prjExternalId, String profileId) throws ProjectNotFoundException {
        Project project = projectsController.findProjectByExternalId(prjExternalId);
        if ((profileId != null) && (!profileId.equals("null"))) { // if profile not null
            Profile profile = profilesController.findProfileById(profileId);
            if (profile.getAllSIByProject(project)){ // if allSI true --> return all factors
                return getQualityFactorsByProject(project);
            } else { // if allSI false --> return filtered factors
                List<ProfileProjectStrategicIndicators> ppsiList =
                        profileProjectStrategicIndicatorsRepository.findByProfileAndProject(profile,project);
                List<Factor> result = new ArrayList<>();
                for (ProfileProjectStrategicIndicators ppsi : ppsiList) {
                    List<StrategicIndicatorQualityFactors> siqfList = ppsi.getStrategicIndicator().getStrategicIndicatorQualityFactorsList();
                    for(StrategicIndicatorQualityFactors siqf : siqfList) {
                        if (!result.contains(siqf.getFactor())) // check to avoid repeated factors
                            result.add(siqf.getFactor());
                    }
                }
                return result;
            }
        } else { // if profile is null --> return all factors
            return getQualityFactorsByProject(project);
        }
    }
}
