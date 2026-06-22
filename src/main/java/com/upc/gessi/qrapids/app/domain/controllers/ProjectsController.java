package com.upc.gessi.qrapids.app.domain.controllers;

import com.upc.gessi.qrapids.app.domain.adapters.Backlog;
import com.upc.gessi.qrapids.app.domain.adapters.QMA.QMAProjects;
import com.upc.gessi.qrapids.app.domain.exceptions.ProjectAlreadyAnonymizedException;
import com.upc.gessi.qrapids.app.domain.exceptions.ElementAlreadyPresentException;
import com.upc.gessi.qrapids.app.domain.models.*;
import com.upc.gessi.qrapids.app.domain.repositories.Profile.ProfileProjectsRepository;
import com.upc.gessi.qrapids.app.domain.repositories.Profile.ProfileRepository;
import com.upc.gessi.qrapids.app.domain.repositories.Project.ProjectRepository;
import com.upc.gessi.qrapids.app.domain.repositories.Student.StudentRepository;
import com.upc.gessi.qrapids.app.domain.repositories.ProjectIdentityRepository.ProjectIdentityRepository;
import com.upc.gessi.qrapids.app.domain.repositories.StudentIdentity.StudentIdentityRepository;
import com.upc.gessi.qrapids.app.domain.repositories.Metric.MetricRepository;
import com.upc.gessi.qrapids.app.domain.repositories.QualityFactor.QualityFactorRepository;
import com.upc.gessi.qrapids.app.domain.repositories.StrategicIndicator.StrategicIndicatorRepository;
import com.upc.gessi.qrapids.app.domain.utils.AnonymizationModes;
import com.upc.gessi.qrapids.app.presentation.rest.dto.*;
import com.upc.gessi.qrapids.app.domain.exceptions.CategoriesException;
import com.upc.gessi.qrapids.app.domain.exceptions.ProjectNotFoundException;
import com.upc.gessi.qrapids.app.presentation.rest.dto.DTOPhase;
import com.upc.gessi.qrapids.app.presentation.rest.dto.DTOProject;
import com.upc.gessi.qrapids.app.presentation.rest.services.exceptions.InternalErrorException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import javax.transaction.Transactional;
import java.io.IOException;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class ProjectsController {

    @Autowired
    private ProjectRepository projectRepository;

    @Autowired
    private ProjectIdentityRepository projectIdentityRepository;

    @Autowired
    private ProfileRepository profileRepository;

    @Autowired
    private StudentsController studentsController;

    @Autowired
    private StudentRepository studentRepository;

    @Autowired
    private StudentIdentityRepository studentIdentityRepository;

    @Autowired
    private MetricRepository metricRepository;

    @Autowired
    private QualityFactorRepository qualityFactorRepository;

    @Autowired
    private StrategicIndicatorRepository strategicIndicatorRepository;

    @Autowired
    private QMAProjects qmaProjects;

    @Autowired
    private Backlog backlog;

    @Autowired
    private ProfileProjectsRepository profileProjectsRepository;

    private Logger logger = LoggerFactory.getLogger(ProjectsController.class);

    public Project findProjectByExternalId(String externalId) throws ProjectNotFoundException {
        Project project = projectRepository.findByExternalId(externalId);
        if (project == null) {
            throw new ProjectNotFoundException(externalId);
        }
        return project;
    }

    public Map<DataSource, DTOProjectIdentity> getProjectIdentitiesByProject(Project project) {
        List<ProjectIdentity> projectIdentities = projectIdentityRepository.findAllByProject(project);

        Map<DataSource, DTOProjectIdentity> dtoProjectIdentities = new HashMap<>();
        projectIdentities.forEach(projectIdentity -> {
            dtoProjectIdentities.put(projectIdentity.getDataSource(),
                    new DTOProjectIdentity(projectIdentity.getDataSource(), projectIdentity.getUrl()));
        });

        return dtoProjectIdentities;
    }

    public DTOProject getProjectByExternalId(String externalId) throws ProjectNotFoundException {
        Project project = projectRepository.findByExternalId(externalId);
        return getProjectDTO(project);
    }

    public List<DTOProject> getProjects(Long id) throws ProjectNotFoundException {
        List<DTOProject> projects = new ArrayList<>();
        Iterable<Project> projectIterable;
        if (id == null) { // Without Profile get all Projects
            projectIterable = projectRepository.findAll();
        } else { // With Profile get specific Projects
            Optional<Profile> profileOptional = profileRepository.findById(id);
            Profile profile = profileOptional.get();
            projectIterable = profile.getProjects();
        }
        List<Project> projectsBD = new ArrayList<>();
        projectIterable.forEach(projectsBD::add);
        for (Project p : projectsBD) {
            projects.add(getProjectDTO(p));
        }
        Collections.sort(projects, new Comparator<DTOProject>() {
            @Override
            public int compare(DTOProject o1, DTOProject o2) {
                return o1.getName().compareTo(o2.getName());
            }
        });
        return projects;
    }

    public Project getProjectById(Long projectId) throws ProjectNotFoundException {
        Optional<Project> projectOptional = projectRepository.findById(projectId);

        if (!projectOptional.isPresent())
            throw new ProjectNotFoundException(projectId.toString());

        return projectOptional.get();
    }

    public DTOProject getProjectDTOById(Long projectId) throws ProjectNotFoundException {
        DTOProject dtoProject = null;

        Project project = getProjectById(projectId);
        logger.info("Project retrieved: {}", project);
        List<DTOStudent> s = studentsController.getStudentsDTOFromProject(projectId);
        logger.info("Students retrieved for project {}: {}", projectId, s);

        dtoProject = getProjectDTO(project);
        dtoProject.setStudents(s);

        return dtoProject;
    }

    public boolean checkProjectByName(Long id, String name) throws ProjectNotFoundException {
        Project p = projectRepository.findByName(name);
        return (p == null || p.getId() == id);
    }

    public void updateProjectIdentities(Collection<DTOProjectIdentity> dtoProjectIdentities, Project project) {

        List<ProjectIdentity> identities = projectIdentityRepository.findAllByProject(project);

        Map<DataSource, ProjectIdentity> identityMap = new HashMap<>();

        identities.forEach(identity -> {
            identityMap.put(identity.getDataSource(), identity);
        });

        dtoProjectIdentities.forEach(identity -> {

            DataSource currentDataSource = identity.getDataSource();
            if (identityMap.containsKey(currentDataSource)) {
                identityMap.get(currentDataSource).setUrl(identity.getUrl());
            } else {
                identityMap.put(currentDataSource,
                        new ProjectIdentity(identity.getDataSource(), identity.getUrl(), project));
            }
        });

        projectIdentityRepository.saveAll(identityMap.values());
    }

    @Transactional
    public void updateProject(DTOProject dtoProject) {

        Project project = new Project(dtoProject.getExternalId(), dtoProject.getName(), dtoProject.getDescription(),
                dtoProject.getLogo(), dtoProject.getActive(), dtoProject.getIsGlobal(), dtoProject.getSubject());
        project.setId(dtoProject.getId());
        String backlogId = dtoProject.getBacklogId();

        if (backlogId == null || backlogId.equals("null"))
            backlogId = null;

        project.setBacklogId(backlogId);
        projectRepository.save(project);

        updateProjectIdentities(dtoProject.getIdentities().values(), project);
    }

    public List<String> getAllProjectsExternalID() throws IOException, CategoriesException {
        return qmaProjects.getAssessedProjects();
    }

    public List<String> importProjectsAndUpdateDatabase() throws IOException, CategoriesException {
        List<String> projects = getAllProjectsExternalID();
        updateDataBaseWithNewProjects(projects);
        return projects;
    }

    public void updateDataBaseWithNewProjects(List<String> projects) {
        for (String project : projects) {
            Project projectSaved = projectRepository.findByExternalId(project);
            if (projectSaved == null) {
                Project newProject = new Project(project, project, "No description specified", null, true, false, null);
                projectRepository.save(newProject);
            }
        }
    }

    public List<DTOMilestone> getMilestonesForProject(String projectExternalId, LocalDate date)
            throws ProjectNotFoundException {
        Project project = findProjectByExternalId(projectExternalId);
        return backlog.getMilestones(project.getBacklogId(), date);
    }

    public List<DTOPhase> getPhasesForProject(String projectExternalId, LocalDate date)
            throws ProjectNotFoundException {
        Project project = findProjectByExternalId(projectExternalId);
        return backlog.getPhases(project.getBacklogId(), date);
    }

    public DTOProject getProjectDTO(Project project) {
        Map<DataSource, DTOProjectIdentity> dtoProjectIdentities = getProjectIdentitiesByProject(project);
        return new DTOProject(project.getId(), project.getExternalId(), project.getName(), project.getDescription(),
                project.getLogo(), project.getActive(), project.getBacklogId(), project.getIsGlobal(),
                dtoProjectIdentities, project.isAnonymized(), project.getSubject());
    }

    public DTOProject anonymizeProject(Project project, AnonymizationModes anonymizationMode) {
        studentsController.anonymizeStudentsFromProject(project, anonymizationMode);

        project.setAnonymized(true);
        projectRepository.save(project);

        return getProjectDTO(project);
    }

    public List<DTOProject> anonymizeProjects(List<Long> projectIds, AnonymizationModes anonymizationMode)
            throws ProjectNotFoundException, ProjectAlreadyAnonymizedException {
        List<DTOProject> dtoProjects = new ArrayList<>();

        List<Project> projects = (List<Project>) projectRepository.findAllById(projectIds);

        List<Long> projectIdsAlreadyAnonymized = new ArrayList<>();

        projects.forEach(project -> {
            if (project.isAnonymized())
                projectIdsAlreadyAnonymized.add(project.getId());
        });

        if (projectIdsAlreadyAnonymized.size() > 0) {

            List<String> projectIdsAlreadyAnonymizedParsed = projectIdsAlreadyAnonymized.stream().map(Object::toString)
                    .collect(Collectors.toList());

            throw new ProjectAlreadyAnonymizedException(projectIdsAlreadyAnonymizedParsed);
        }

        projects.forEach(project -> {
            dtoProjects.add(anonymizeProject(project, anonymizationMode));
        });

        return dtoProjects;
    }

    /////////////////////////////////////////////// NEW CODE
    /////////////////////////////////////////////// //////////////////////////////////////////////////////
    public DTOProject createProject(DTOProject dto) throws ElementAlreadyPresentException {
        // Comprovem si el projecte ja existeix a la BD
        Project existingProject = projectRepository.findByExternalId(dto.getExternalId());
        if (existingProject != null) {
            throw new ElementAlreadyPresentException(
                    "Project with external ID " + dto.getExternalId() + " already exists.");
        }

        // Creem un nou objecte Project de domini
        Project newProject = new Project();
        newProject.setexternalId(dto.getExternalId());
        newProject.setName(dto.getName());
        newProject.setDescription(dto.getDescription() != null ? dto.getDescription() : "No description specified");
        newProject.setLogo(dto.getLogo());
        newProject.setActive(true);
        newProject.setIsGlobal(false);
        newProject.setAnonymized(false);
        newProject.setSubject(dto.getSubject());

        // Guardem el nou projecte a la BD
        Project savedProject = projectRepository.save(newProject);

        // Tornem un DTOProject amb la informació del projecte creat
        DTOProject createdDTO = new DTOProject();
        createdDTO.setId(savedProject.getId());
        createdDTO.setexternalId(savedProject.getExternalId());
        createdDTO.setName(savedProject.getName());
        createdDTO.setDescription(savedProject.getDescription());
        createdDTO.setLogo(savedProject.getLogo());
        createdDTO.setActive(savedProject.getActive());
        createdDTO.setBacklogId(savedProject.getBacklogId());
        createdDTO.setIsGlobal(savedProject.getIsGlobal());
        createdDTO.setAnonymized(savedProject.isAnonymized());
        createdDTO.setSubject(savedProject.getSubject());

        if (dto.getIdentities() != null && !dto.getIdentities().isEmpty()) {
            // Guardem les identitats associades al projecte
            updateProjectIdentities(dto.getIdentities().values(), savedProject);
            createdDTO.setIdentities(dto.getIdentities());
        } else {
            createdDTO.setIdentities(new HashMap<>());
        }
        return createdDTO;
    }

    public DTOStudent createStudentForProject(Long projectId, DTOStudent dto) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Project not found"));

        // Crea el nou estudiant
        Student student = new Student();
        student.setName(dto.getName());
        student.setProject(project);
        studentRepository.save(student);

        // Afegir identitats si n’hi ha al DTO
        if (dto.getIdentities() != null) {
            for (DTOStudentIdentity id : dto.getIdentities().values()) {
                StudentIdentity identity = new StudentIdentity(id.getDataSource(), id.getUsername(), student);
                studentIdentityRepository.save(identity);
            }
        }
        DTOStudent savedDTO = new DTOStudent();
        savedDTO.setId(student.getId());
        savedDTO.setName(student.getName());
        return savedDTO;
    }

    @Transactional
    public void deleteProject(Long id) {
        Project project = projectRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Project not found"));
        List<Student> students = studentRepository.findAllByProjectId(id);
        studentIdentityRepository.deleteAllByStudentIn(students);
        studentRepository.deleteAllByProjectId(id);
        metricRepository.deleteAllByProjectId(id);
        qualityFactorRepository.deleteAllByProjectId(id);
        strategicIndicatorRepository.deleteAllByProjectId(id);
        projectIdentityRepository.deleteAllByProject(project);
        projectRepository.deleteById(id);

    }
}
