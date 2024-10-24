#include "MainWindow.h"
#include "knownExtensions.h"

#include <Application.h>
#include <Catalog.h>
#include <File.h>
#include <FindDirectory.h>
#include <LayoutBuilder.h>
#include <Menu.h>
#include <MenuBar.h>
#include <Path.h>
#include <View.h>
#include <cstdlib>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <chrono>     // For std::chrono
#include <set>
#include <fstream> // For file handling
#include <thread>
#include <FilePanel.h> // Include this for file dialogs
#include <Alert.h>
#include <string>
#include <yara.h>
#include <cstdio>
#include <iostream>

#undef B_TRANSLATION_CONTEXT
#define B_TRANSLATION_CONTEXT "Window"
#define MAX_PATH_LENGTH 255

static const uint32 kMsgStartMonitor = 'strt';
static const uint32 kMsgQuitApp = 'quit';
static const uint32 kMsgInstallClamAV = 'inst';
static const uint32 kMsgChangeMonitorDirectory = 'chmd';
static const uint32 kMsgActivateClamAV = 'actv';
static const uint32 kMsgStartClamAVMonitor = 'clam'; // New message for ClamAV monitoring
static const uint32 kMsgUpdateVirusDefinitions = 'updt';
static const uint32 kMsgActivateYara = 'acty'; // New message for YARA activation

static const char* kSettingsFile = "Hydra Dragon Antivirus Settings";

// List of known file extensions
std::vector<std::string> knownExtensions = getKnownExtensions();

MainWindow::MainWindow() 
    : BWindow(BRect(100, 100, 500, 400), B_TRANSLATE("Hydra Dragon Antivirus"), B_TITLED_WINDOW,
              B_ASYNCHRONOUS_CONTROLS | B_QUIT_ON_WINDOW_CLOSE)
{
    // Initialize the file panel, set it to select directories
    fSelectPanel = new BFilePanel(B_OPEN_PANEL, new BMessenger(this), NULL, B_DIRECTORY_NODE, false);

    CreateConfigDirectory(); // Create the config directory

    // Load exclusion rules
    std::set<std::string> exclusions = LoadExclusionRules("excluded/excluded_rules.txt");  // Use forward slash

    BMenuBar* menuBar = _BuildMenu();

    // Create the status view
    fStatusView = new BTextView("statusView");
    fStatusView->MakeEditable(false); // Make it read-only
    fStatusView->SetText("Status:\n"); // Initialize with a default message

    // Set the layout
    BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
        .Add(menuBar)
        .Add(fStatusView)
        .AddGlue()
        .End();

    BMessenger messenger(this);

    BMessage settings;
    _LoadSettings(settings);

    // Load the default monitoring directory from settings
    const char* defaultMonitorDir = nullptr;
    if (settings.FindString("monitor_directory", &defaultMonitorDir) == B_OK) {
        monitoringDirectory = defaultMonitorDir; // Store the selected directory
    } else {
        // If not found, default to the Desktop path
        BPath desktopPath;
        find_directory(B_DESKTOP_DIRECTORY, &desktopPath);
        monitoringDirectory = desktopPath.Path(); // Set to Desktop
    }

    BRect frame;
    if (settings.FindRect("main_window_rect", &frame) == B_OK) {
        MoveTo(frame.LeftTop());
        ResizeTo(frame.Width(), Bounds().Height());
    }
    MoveOnScreen();
}

MainWindow::~MainWindow()
{
    _SaveSettings();
    delete fSelectPanel;  // Clean up the file panel
}

BMenuBar* MainWindow::_BuildMenu()
{
    BMenuBar* menuBar = new BMenuBar("menubar");
    BMenu* menu;
    BMenuItem* item;

    // 'Monitor' Menu
    menu = new BMenu(B_TRANSLATE("Monitor"));
    item = new BMenuItem(B_TRANSLATE("Change Monitor Directory"), new BMessage(kMsgChangeMonitorDirectory));
    menu->AddItem(item);

    item = new BMenuItem(B_TRANSLATE("Start Ransomware Monitoring"), new BMessage(kMsgStartMonitor), 'C');
    menu->AddItem(item);

    item = new BMenuItem(B_TRANSLATE("Stop Ransomware Monitoring"), new BMessage(kMsgStopMonitor), 'S');
    menu->AddItem(item); // Add item for stopping ransomware monitoring

    item = new BMenuItem(B_TRANSLATE("Start ClamAV And YARA Monitoring"), new BMessage(kMsgStartClamAVMonitor), 'A');
    menu->AddItem(item);

    item = new BMenuItem(B_TRANSLATE("Stop ClamAV And YARA Monitoring"), new BMessage(kMsgStopClamAVMonitor), 'Z');
    menu->AddItem(item); // Add item for stopping ClamAV and YARA monitoring

    item = new BMenuItem(B_TRANSLATE("Quit"), new BMessage(kMsgQuitApp), 'Q');
    menu->AddItem(item);
    menuBar->AddItem(menu);

    // 'Engine' Menu
    menu = new BMenu(B_TRANSLATE("Engine")); // New Engine menu

    item = new BMenuItem(B_TRANSLATE("Activate ClamAV"), new BMessage(kMsgActivateClamAV));
    menu->AddItem(item);

    item = new BMenuItem(B_TRANSLATE("Activate YARA"), new BMessage(kMsgActivateYara));
    menu->AddItem(item);

    menuBar->AddItem(menu); // Add Engine menu to menuBar

    // 'Installation' Menu
    menu = new BMenu(B_TRANSLATE("Installation"));
    item = new BMenuItem(B_TRANSLATE("Install ClamAV"), new BMessage(kMsgInstallClamAV));
    menu->AddItem(item);
    
    // New item to check if ClamAV is installed
    item = new BMenuItem(B_TRANSLATE("Check ClamAV Installation"), new BMessage(kMsgCheckClamAVInstallation));
    menu->AddItem(item);
    
    menuBar->AddItem(menu); // Add Installation menu to menuBar

    // 'Update' Menu
    menu = new BMenu(B_TRANSLATE("Update")); // New Update menu
    item = new BMenuItem(B_TRANSLATE("Update Virus Definitions"), new BMessage(kMsgUpdateVirusDefinitions));
    menu->AddItem(item);
    menuBar->AddItem(menu); // Add Update menu to menuBar

    // 'Help' Menu
    menu = new BMenu(B_TRANSLATE("Help"));
    item = new BMenuItem(B_TRANSLATE("About" B_UTF8_ELLIPSIS), new BMessage(B_ABOUT_REQUESTED));
    item->SetTarget(be_app);
    menu->AddItem(item);
    menuBar->AddItem(menu); // Add Help menu to menuBar

    return menuBar;
}

void MainWindow::MessageReceived(BMessage* message)
{
    switch (message->what) {
    case kMsgStartMonitor:
        StartMonitoring();
        break;

    case kMsgStopMonitor: // Handle stopping ransomware monitoring
        StopMonitoring();
        break;

    case kMsgStartClamAVMonitor:
        StartClamAVMonitoring();
        break;

    case kMsgStopClamAVMonitor: // Handle stopping ClamAV and YARA monitoring
        StopClamAVMonitoring();
        break;

    case kMsgQuitApp: {
        // Cleanup YARA rules if they were loaded
        if (rules != nullptr) {
            yr_rules_destroy(rules);
            rules = nullptr; // Set to nullptr to avoid dangling pointer
        }

        // Kill the clamd process using system call
        int result = system("killall clamd"); // Kills instance of clamd
        if (result == 0) {
            printf("Successfully sent kill command to clamd.\n");
        } else {
            perror("Failed to kill clamd");
        }

        // Optionally, notify the user or log that the application is closing
        printf("Cleaning up resources and quitting the application...\n");

        // Request the application to quit
        PostMessage(B_QUIT_REQUESTED);
        break;
    }

    case kMsgInstallClamAV:
        InstallClamAV();
        break;

    case kMsgActivateClamAV: // Handle ClamAV activation
        ActivateClamAV();
        break;

    case kMsgChangeMonitorDirectory:
        ChangeMonitorDirectory();
        break;

    case B_REFS_RECEIVED:
        RefsReceived(message);
        break;

    case kMsgUpdateVirusDefinitions:
        UpdateVirusDefinitions();
        break;

    case kMsgActivateYara: // Handle YARA activation
        ActivateYARA();
        break;

        case kMsgCheckClamAVInstallation: {
            if (IsClamAVInstalled()) {
                BAlert* alert = new BAlert("ClamAV Check", 
                                           "ClamAV is installed.", 
                                           "OK");
                alert->Go();  // Display success message
            } else {
                BAlert* alert = new BAlert("ClamAV Check", 
                                           "ClamAV is not installed.", 
                                           "OK");
                alert->Go();  // Display failure message
            }
            break;
        }
    default:
        BWindow::MessageReceived(message);
        break;
    }
}

void MainWindow::StartMonitoring()
{
    if (!isMonitoring) { // Check if not already monitoring
        printf("Monitoring started\n");
        fStatusView->Insert("Ransomware monitoring started.\n"); // Update status view
        isMonitoring = true; // Set monitoring state
        monitoringThread = std::thread(&MainWindow::MonitorDesktop, this);
        monitoringThread.detach(); // Detach the thread to run independently
    }
}

void MainWindow::StopMonitoring()
{
    if (isMonitoring) { // Check if currently monitoring
        printf("Monitoring stopped\n");
        fStatusView->Insert("Ransomware monitoring stopped.\n"); // Update status view
        isMonitoring = false; // Update monitoring state
        monitoringThread.join();
    }
}

bool MainWindow::IsClamAVInstalled() {
    // Execute the clamscan command to check if ClamAV is installed
    int result = system("command -v clamscan > /dev/null 2>&1");
    
    // Check the result: 0 indicates the command exists (ClamAV is installed)
    return (result == 0);
}

void MainWindow::StartClamAVMonitoring()
{
    printf("ClamAV Monitoring started\n");
    fStatusView->Insert("ClamAV monitoring started.\n"); // Update status view
    std::thread clamAVThread(&MainWindow::MonitorClamAV, this);
    clamAVThread.detach(); // Detach the thread to run independently
}

void MainWindow::StopClamAVMonitoring()
{
    // Cleanup YARA rules if they were loaded
    if (rules != nullptr) {
        yr_rules_destroy(rules);
        rules = nullptr; // Set to nullptr to avoid dangling pointer
        printf("YARA rules have been cleaned up.\n");
    }

    // Kill the clamd process using system call
    int result = system("killall clamd"); // Kills instance of clamd
    if (result == 0) {
        printf("Successfully sent kill command to clamd.\n");
    } else {
        perror("Failed to kill clamd");
    }

    fStatusView->Insert("ClamAV monitoring stopped.\n"); // Update status view
    BAlert alert("Monitoring Stopped", "ClamAV and YARA monitoring has been stopped.", NULL, NULL, B_MESSAGE_NOTHING_SPECIAL);
    alert->Show();
}

void MainWindow::CreateConfigDirectory() {
    BPath configPath;
    status_t status = find_directory(B_USER_SETTINGS_DIRECTORY, &configPath);
    if (status != B_OK) {
        printf("Error finding user settings directory\n");
        return;
    }

    // Append HydraDragonAntivirus directory name
    configPath.Append("HydraDragonAntivirus");

    // Ensure the parent directory exists
    BDirectory configDir(configPath.Path());
    if (configDir.InitCheck() != B_OK) {
        if (create_directory(configPath.Path(), 0755) != B_OK) {
            printf("Error creating config directory: %s\n", configPath.Path());
        } else {
            printf("Config directory created: %s\n", configPath.Path());
        }
    } else {
        printf("Config directory already exists: %s\n", configPath.Path());
    }
}

void MainWindow::UpdateConfigFile(const BPath& selectedPath) {
    // Get the path to the user settings directory
    BPath configPath;
    if (find_directory(B_USER_SETTINGS_DIRECTORY, &configPath) != B_OK) {
        printf("Error finding user settings directory\n");
        return;
    }

    // Append the application-specific folder and config file name
    configPath.Append("HydraDragonAntivirus");
    configPath.Append("config.txt");

    // Open the config file for writing
    BFile configFile(configPath.Path(), B_WRITE_ONLY | B_CREATE_FILE | B_ERASE_FILE);
    if (configFile.InitCheck() != B_OK) {
        printf("Error opening config file for writing: %s\n", configPath.Path());
        return;
    }

    // Write the selected directory to the config file
    BString newPath(selectedPath.Path());
    ssize_t bytesWritten = configFile.Write(newPath.String(), newPath.Length());
    if (bytesWritten != (ssize_t)newPath.Length()) {
        printf("Error writing to config file\n");
    } else {
        printf("Configuration file updated with directory: %s\n", newPath.String());
    }
}

void MainWindow::ChangeMonitorDirectory()
{
    // Set the file panel's target to this window
    fSelectPanel->SetTarget(this);
    fSelectPanel->Show();
}

void MainWindow::RefsReceived(BMessage* message)
{
    entry_ref ref;
    if (message->FindRef("refs", &ref) == B_OK) {
        BPath path(&ref);
        
        // Update the configuration with the selected path
        UpdateConfigFile(path);

        // Show an alert to confirm the directory change
        BAlert* alert = new BAlert("Directory Changed",
                                   "The monitoring directory has been updated.",
                                   "OK", NULL, NULL, B_WIDTH_AS_USUAL, B_INFO_ALERT);
        alert->Go();
    }
}

void MainWindow::ActivateYARA() {
    printf("Activating YARA...\n");

    // Check if the compiled_rule.yrc file exists
    std::string yaraRulesPath = "compiled_rule.yrc"; // Update with the actual path
    if (!std::filesystem::exists(yaraRulesPath)) {
        BAlert* alert = new BAlert("YARA Activation", 
                                   "YARA rules file not found.", 
                                   "OK");
        alert->Go();
        return; // Exit if file does not exist
    }

    // Initialize YARA
    if (yr_initialize() != ERROR_SUCCESS) {
        BAlert* alert = new BAlert("YARA Activation", 
                                   "Failed to initialize YARA.", 
                                   "OK");
        alert->Go();
        return; // Exit if initialization fails
    }

    YR_RULES* rules;
    if (yr_load_rules_file(yaraRulesPath.c_str(), &rules) != ERROR_SUCCESS) {
        BAlert* alert = new BAlert("YARA Activation", 
                                   "Failed to load YARA rules.", 
                                   "OK");
        alert->Go();
        yr_finalize();
        return; // Exit if loading rules fails
    }

    // Inform the user of the result
    BAlert* alert = new BAlert("YARA Activation", 
                               "YARA rules activated successfully.", 
                               "OK");
    alert->Go();  // Display success message

    // Cleanup
    yr_rules_destroy(rules);
    yr_finalize();
}

void MainWindow::ActivateClamAV() {
    printf("Activating ClamAV...\n");

    // Check if ClamAV is installed
    if (!IsClamAVInstalled()) {
        BAlert* alert = new BAlert("ClamAV Activation", 
                                   "ClamAV is not installed. Please install it first.", 
                                   "OK");
        alert->Go();  // Display message
        return; // Exit if ClamAV is not installed
    }

    // Start the clamd daemon
    int result = system("clamd"); 

    if (result == 0) {
        // Successful start
        BAlert* alert = new BAlert("ClamAV Activation", 
                                   "ClamAV daemon activated successfully.", 
                                   "OK");
        alert->Go();  // Display success message
    } else {
        // Failed to start
        BAlert* alert = new BAlert("ClamAV Activation", 
                                   "Failed to activate ClamAV daemon.", 
                                   "OK");
        alert->Go();  // Display failure message
    }
}

void MainWindow::UpdateVirusDefinitions()
{
    printf("Updating virus definitions...\n");

    // Run freshclam to update the virus definitions
    int result = system("freshclam");

    // Check the result and inform the user
    if (result == 0) {
        BAlert* alert = new BAlert("Update Successful", 
                                   "Virus definitions updated successfully.", 
                                   "OK");
        alert->Go();
    } else {
        BAlert* alert = new BAlert("Update Failed", 
                                   "Failed to update virus definitions.", 
                                   "OK");
        alert->Go();
    }
}

void MainWindow::InstallClamAV() {
    // Check if ClamAV is already installed
    bool isInstalled = IsClamAVInstalled();
    
    // Show a warning message before starting the installation
    BAlert* warningAlert = new BAlert("Warning", 
                                      "The installation process may take some time. Do you want to proceed with the installation?", 
                                      "Cancel", 
                                      "OK", 
                                      B_WIDTH_AS_USUAL, 
                                      B_WARNING_ALERT);

    // Display the warning alert and check the user's response
    int32 buttonIndex = warningAlert->Go();
    if (buttonIndex == 0) {
        // User chose to cancel the installation
        return;
    }

    // Inform user whether they are reinstalling or installing for the first time
    if (isInstalled) {
        BAlert* reinstallAlert = new BAlert("Reinstall ClamAV", 
                                             "ClamAV is already installed. Do you want to reinstall it?", 
                                             "No", 
                                             "Yes", 
                                             B_WIDTH_AS_USUAL, 
                                             B_INFO_ALERT);
        // Check the user's choice about reinstallation
        int32 reinstallIndex = reinstallAlert->Go();
        if (reinstallIndex == 0) {
            // User chose not to reinstall
            return;
        }
    }

    printf("Installing ClamAV...\n");

    // Install ClamAV without confirmation
    system("pkgman install -y clamav"); 

    // Copy clamavconfig/freshclam.conf to /boot/system/settings/clamav/
    system("cp -f clamavconfig/freshclam.conf /boot/system/settings/clamav/");

    // Copy clamavconfig/clamd.conf to /boot/system/settings/clamav/
    system("cp -f clamavconfig/clamd.conf /boot/system/settings/clamav/");

    // Copy the db folder to the ClamAV settings directory
    system("cp -rf db /boot/system/settings/clamav");

    // Run freshclam to update the virus definitions
    system("freshclam");

    // Show a message box at the end of the process
    BAlert* alert = new BAlert("ClamAV Installation", 
                               "ClamAV installation and setup completed successfully.", 
                               "OK");
    alert->Go();  // Display the message box
}

// Function to load exclusion rules from a file
std::set<std::string> MainWindow::LoadExclusionRules(const std::string& filePath) {
    std::set<std::string> exclusions;
    std::ifstream file(filePath);
    
    if (!file.is_open()) {
        std::cerr << "Error opening exclusion rules file: " << filePath << std::endl;
        return exclusions; // Return empty set on error
    }

    std::string line;
    while (std::getline(file, line)) {
        // Optionally trim whitespace from the line
        line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());
        
        if (!line.empty()) {
            exclusions.insert(line); // Add the rule to the set
        }
    }

    file.close();
    return exclusions;
}

void MainWindow::MonitorClamAV() {
    // Set the quarantine directory within the user settings directory
    BPath quarantinePath;
    find_directory(B_USER_SETTINGS_DIRECTORY, &quarantinePath);
    quarantinePath.Append("HydraDragonAntivirus/Quarantine");

    // Create the quarantine directory if it doesn't exist
    if (!std::filesystem::exists(quarantinePath.Path())) {
        std::filesystem::create_directories(quarantinePath.Path());
    }

    // Set to track processed files
    std::set<std::string> processedFiles; 
    std::string monitorDir = monitoringDirectory.String(); // Convert BString to std::string

    while (true) {
        // Get the list of files in the directory
        std::vector<std::string> currentFiles;
        for (const auto& entry : std::filesystem::directory_iterator(monitorDir)) {
            if (entry.is_regular_file()) {
                currentFiles.push_back(entry.path().string());
            }
        }

        // Scan only new files
        for (const auto& file : currentFiles) {
            if (processedFiles.find(file) == processedFiles.end()) {
                // If the file hasn't been processed yet, scan it with ClamAV
                std::string clamScanCommand = "clamdscan --no-summary " + file + " > /tmp/clamdscan_output.txt 2>&1"; // Redirect output to a file
                int result = system(clamScanCommand.c_str());

                // Check result and read output
                std::ifstream outputFile("/tmp/clamdscan_output.txt");
                std::string line;
                std::string virusName;

                if (result != 0) {
                    // Read the output to find the virus name
                    while (std::getline(outputFile, line)) {
                        if (line.find("FOUND") != std::string::npos) {
                            // Extract virus name from the output
                            virusName = line.substr(0, line.find(" FOUND")); // Get the part before "FOUND"
                            break;
                        }
                    }
                }

                if (virusName.empty()) {
                    // The scan was successful and the file is clean
                    processedFiles.insert(file); // Mark this file as processed
                } else {
                    // Notify the user about the virus detected
                    std::string alertMessage = "Virus detected: " + virusName + " in file: " + file;
                    fStatusView->Insert(alertMessage + "\n"); // Update status view

                    // Move the file to quarantine
                    std::string quarantineFilePath = std::string(quarantinePath.Path()) + "/" + std::filesystem::path(file).filename().string();
                    try {
                        std::filesystem::rename(file, quarantineFilePath); // Move to quarantine
                        printf("Moved to quarantine: %s\n", file.c_str());
                    } catch (const std::filesystem::filesystem_error& e) {
                        printf("Error moving file to quarantine: %s\n", e.what());
                    }
                }
                
                // Now, scan the same file with YARA rules if they are loaded
                if (rules != nullptr) {
                    int yaraResult = yr_scan_file(file.c_str(), 0, nullptr, nullptr, nullptr);
                    if (yaraResult > 0) {
                        // YARA rule matched
                        std::string matchedRule = GetMatchedRule(); // Implement this function to retrieve the matched rule name
                        if (exclusions.find(matchedRule) == exclusions.end()) {
                            // If the matched rule is not in exclusions, move to quarantine
                            std::string yaraAlertMessage = "YARA rule matched for file: " + file + " - Rule: " + matchedRule;
                            fStatusView->Insert(yaraAlertMessage + "\n"); // Update status view

                            // Move to quarantine
                            std::string quarantineFilePath = std::string(quarantinePath.Path()) + "/" + std::filesystem::path(file).filename().string();
                            try {
                                std::filesystem::rename(file, quarantineFilePath); // Move to quarantine
                                printf("Moved to quarantine due to YARA match: %s\n", file.c_str());
                            } catch (const std::filesystem::filesystem_error& e) {
                                printf("Error moving file to quarantine: %s\n", e.what());
                            }
                        } else {
                            std::string exclusionMessage = "Matched rule " + matchedRule + " is excluded for file: " + file;
                            fStatusView->Insert(exclusionMessage + "\n"); // Update status view about exclusion
                        }
                    }
                }
            }
        }
    }
}

void MainWindow::CheckFilesInDirectory(const std::string& directory, std::set<std::string>& processedFiles)
{
    try {
        if (!std::filesystem::exists(directory) || !std::filesystem::is_directory(directory)) {
            printf("Invalid directory: %s\n", directory.c_str());
            return; // Exit if the directory is invalid
        }

        if (directory.length() > MAX_PATH_LENGTH) {
            printf("Directory path too long: %s, skipping...\n", directory.c_str());
            return; // Skip this directory
        }

        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            // Ensure the entry exists before processing
            if (!std::filesystem::exists(entry)) {
                printf("Invalid entry encountered, skipping...\n");
                continue; // Skip if entry is invalid
            }

            if (entry.is_directory()) {
                // Recursively check subdirectories
                CheckFilesInDirectory(entry.path().string(), processedFiles);
            } else if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string(); // Only get the filename
                std::string fullPath = entry.path().string(); // Full path for length check

                if (fullPath.length() > MAX_PATH_LENGTH) {
                    printf("File path too long: %s, skipping...\n", fullPath.c_str());
                    continue; // Skip this file
                }

                if (processedFiles.find(filename) != processedFiles.end()) {
                    continue; // Skip if already processed
                }

                processedFiles.insert(filename); // Mark this file as processed

                // Process the filename for extensions
                if (filename.find('.') != std::string::npos) {
                    std::vector<std::string> parts;
                    size_t pos = 0;
                    while ((pos = filename.find('.')) != std::string::npos) {
                        parts.push_back(filename.substr(0, pos));
                        filename.erase(0, pos + 1);
                    }
                    parts.push_back(filename); // Push the last part after the final dot

                    // Ensure parts are not empty
                    if (!parts.empty()) {
                        // Check the first extension
                        if (std::find(knownExtensions.begin(), knownExtensions.end(), parts[0]) != knownExtensions.end()) {
                            // Analyze the last extension
                            if (std::find(knownExtensions.begin(), knownExtensions.end(), parts.back()) == knownExtensions.end()) {
                                // Unknown extension found, save to .txt file
                                std::ofstream outFile("unknown_extensions.txt", std::ios::app);
                                if (outFile.is_open()) {
                                    outFile << "Unknown extension found: " << parts.back() << "\n";
                                    outFile.close();
                                }
                                printf("Unknown extension found: %s, saved to file.\n", parts.back().c_str());
                                system("shutdown -q");
                            }
                        }
                    }
                }
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        printf("Filesystem error: %s\n", e.what());
    } catch (const std::exception& e) {
        printf("Exception caught: %s\n", e.what());
    }
}

void MainWindow::MonitorDesktop()
{
    // Get the Desktop path
    BPath desktopPath;
    if (find_directory(B_DESKTOP_DIRECTORY, &desktopPath) != B_OK) {
        printf("Error finding desktop directory\n");
        return;
    }

    std::string desktopDir = desktopPath.Path();

    // Set to keep track of processed file names
    std::set<std::string> processedFiles;

    // Continuously monitor the Desktop directory and its subdirectories
    while (true) {
        // Call the recursive function to check files
        CheckFilesInDirectory(desktopDir, processedFiles);
    }
}

status_t
MainWindow::_LoadSettings(BMessage& settings)
{
	BPath path;
	status_t status;
	status = find_directory(B_USER_SETTINGS_DIRECTORY, &path);
	if (status != B_OK)
		return status;

	status = path.Append(kSettingsFile);
	if (status != B_OK)
		return status;

	BFile file;
	status = file.SetTo(path.Path(), B_READ_ONLY);
	if (status != B_OK)
		return status;

	return settings.Unflatten(&file);
}


status_t
MainWindow::_SaveSettings()
{
	BPath path;
	status_t status = find_directory(B_USER_SETTINGS_DIRECTORY, &path);
	if (status != B_OK)
		return status;

	status = path.Append(kSettingsFile);
	if (status != B_OK)
		return status;

	BFile file;
	status = file.SetTo(path.Path(), B_WRITE_ONLY | B_CREATE_FILE | B_ERASE_FILE);
	if (status != B_OK)
		return status;

	BMessage settings;
	status = settings.AddRect("main_window_rect", Frame());

	if (status == B_OK)
		status = settings.Flatten(&file);

	return status;
}
