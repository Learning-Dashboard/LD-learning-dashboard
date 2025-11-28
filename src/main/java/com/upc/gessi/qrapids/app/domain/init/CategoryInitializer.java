package com.upc.gessi.qrapids.app.domain.init;

import javax.annotation.PostConstruct;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import com.upc.gessi.qrapids.app.domain.models.MetricCategory;
import com.upc.gessi.qrapids.app.domain.models.QFCategory;
import com.upc.gessi.qrapids.app.domain.models.SICategory;
import com.upc.gessi.qrapids.app.domain.repositories.MetricCategory.MetricCategoryRepository;
import com.upc.gessi.qrapids.app.domain.repositories.QFCategory.QFCategoryRepository;
import com.upc.gessi.qrapids.app.domain.repositories.SICategory.SICategoryRepository;

@Component
public class CategoryInitializer {

    @Autowired
    private MetricCategoryRepository metricCategoryRepository;

    @Autowired
    private QFCategoryRepository factorCategoryRepository;

    @Autowired
    private SICategoryRepository strategicIndicatorCategoryRepository;

    private static final String[] NOMS = {"Good", "Neutral", "Bad"};
    private static final String[] COLORS = {"#00ff00", "#ff8000", "#ff0000"};
    private static final float[] VALORS = {1.0f, 0.67f, 0.33f};

    @PostConstruct
    public void initializeDefaultCategory() {
        boolean metricExists = metricCategoryRepository.existsByName("Default");
        if (!metricExists) {
            for (int i = 0; i < NOMS.length; i++) metricCategoryRepository.save(new MetricCategory("Default", null, COLORS[i], VALORS[i], NOMS[i]));

        }
        boolean factorExists = factorCategoryRepository.existsByName("Default");
        if (!factorExists) {
            for (int i = 0; i < NOMS.length; i++) factorCategoryRepository.save(new QFCategory("Default", null, COLORS[i], VALORS[i], NOMS[i]));
        }
        for (int i = 0; i < NOMS.length; i++) {
            if (!strategicIndicatorCategoryRepository.existsByName(NOMS[i])) {
                strategicIndicatorCategoryRepository.save(new SICategory(NOMS[i], COLORS[i]));
            }
        }
    }
}
