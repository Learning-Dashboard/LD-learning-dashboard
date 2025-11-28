package com.upc.gessi.qrapids.app.presentation.rest.dto;

public class DTOCategoryThreshold extends DTOCategory {

    private String patternGroup;
    private float upperThreshold;

    public DTOCategoryThreshold(Long id, String name, String patternGroup, String color, float upperThreshold) {
        super(id,  name, color);
        this.patternGroup = patternGroup;
        this.upperThreshold = upperThreshold;
    }

    public String getPatternGroup() {
        return patternGroup;
    }

    public void setPatternGroup(String patternGroup) {
        this.patternGroup = patternGroup;
    }

    public float getUpperThreshold() {
        return upperThreshold;
    }

    public void setUpperThreshold(float upperThreshold) {
        this.upperThreshold = upperThreshold;
    }
}
