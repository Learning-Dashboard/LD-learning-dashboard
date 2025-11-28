package com.upc.gessi.qrapids.app.presentation.rest.dto;

import com.upc.gessi.qrapids.app.presentation.rest.dto.DTOCategoryThreshold;

public class DTOFactorCategory extends DTOCategoryThreshold {
    private String type;

    public DTOFactorCategory(Long id, String name, String patternGroup, String color, float upperThreshold, String type) {
        super(id, name, patternGroup, color, upperThreshold);
        this.type = type;
    }

    public String getType() {
        return this.type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
