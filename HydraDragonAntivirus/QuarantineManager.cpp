#include "QuarantineManager.h"
#include <LayoutBuilder.h>
#include <Alert.h>
#include <File.h>
#include <Directory.h>
#include <String.h>
#include <Path.h>
#include <FindDirectory.h>
#include <iostream>
#include <fstream>
#include <sstream>

QuarantineManager::QuarantineManager()
    : BWindow(BRect(100, 100, 500, 400), "Quarantine Manager", B_TITLED_WINDOW,
              B_ASYNCHRONOUS_CONTROLS | B_QUIT_ON_WINDOW_CLOSE)
{
    fListView = new BListView("quarantineList");
    LoadQuarantinedFiles(); // Load the files into the list view

    BButton* restoreButton = new BButton("restoreButton", "Restore", new BMessage('rstr'));
    BButton* deleteButton = new BButton("deleteButton", "Delete", new BMessage('delt'));

    BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
        .Add(fListView)
        .Add(restoreButton)
        .Add(deleteButton)
        .End();
}

void QuarantineManager::LoadQuarantinedFiles() {
    BPath logPath;
    find_directory(B_USER_SETTINGS_DIRECTORY, &logPath);
    logPath.Append("HydraDragonAntivirus/quarantine_log.txt"); // Path to the log file

    std::ifstream logFile(logPath.Path());
    std::string line;

    while (std::getline(logFile, line)) {
        if (!line.empty()) {
            // Expect the log format: original_file_path, virus_name, is_PUA
            std::istringstream iss(line);
            std::string originalPath, virusName, isPUA;
            if (std::getline(iss, originalPath, ',') &&
                std::getline(iss, virusName, ',') &&
                std::getline(iss, isPUA)) {
                
                fListView->AddItem(new BStringItem(originalPath.c_str()));
                quarantinedFiles.push_back(originalPath); // Store original file paths
            }
        }
    }
}

void QuarantineManager::MessageReceived(BMessage* message) {
    switch (message->what) {
    case 'rstr':
        RestoreSelectedFile();
        break;
    case 'delt':
        DeleteSelectedFile();
        break;
    default:
        BWindow::MessageReceived(message);
        break;
    }
}

void QuarantineManager::RestoreSelectedFile() {
    int32 selectedIndex = fListView->CurrentSelection();
    if (selectedIndex >= 0) {
        // Get the selected file path
        std::string filePath = quarantinedFiles[selectedIndex];
        
        // Logic to restore the file from quarantine
        BPath quarantinePath;
        find_directory(B_USER_SETTINGS_DIRECTORY, &quarantinePath);
        quarantinePath.Append("HydraDragonAntivirus/Quarantine"); // Quarantine folder path
        
        BPath restoredFilePath(quarantinePath.Path());
        restoredFilePath.Append(std::filesystem::path(filePath).filename().string()); // Get the filename to restore

        // Attempt to move the file back to its original location
        try {
            std::filesystem::rename(restoredFilePath.Path(), filePath); // Move the file back
            BAlert* alert = new BAlert("Restored", "File restored successfully.", "OK");
            alert->Go();
            fListView->RemoveItem(selectedIndex); // Remove from list view
            quarantinedFiles.erase(quarantinedFiles.begin() + selectedIndex); // Remove from vector
        } catch (const std::filesystem::filesystem_error& e) {
            BAlert* alert = new BAlert("Error", "Failed to restore the file: " + std::string(e.what()), "OK");
            alert->Go();
        }
    }
}

void QuarantineManager::DeleteSelectedFile() {
    int32 selectedIndex = fListView->CurrentSelection();
    if (selectedIndex >= 0) {
        // Get the selected file path
        std::string filePath = quarantinedFiles[selectedIndex];

        // Logic to delete the file from quarantine
        BPath quarantinePath;
        find_directory(B_USER_SETTINGS_DIRECTORY, &quarantinePath);
        quarantinePath.Append("HydraDragonAntivirus/Quarantine"); // Quarantine folder path
        
        BPath fileToDelete(quarantinePath.Path());
        fileToDelete.Append(std::filesystem::path(filePath).filename().string()); // Get the filename to delete

        // Attempt to delete the file
        if (std::filesystem::remove(fileToDelete.Path())) {
            BAlert* alert = new BAlert("Deleted", "File deleted successfully.", "OK");
            alert->Go();
            fListView->RemoveItem(selectedIndex); // Remove from list view
            quarantinedFiles.erase(quarantinedFiles.begin() + selectedIndex); // Remove from vector
        } else {
            BAlert* alert = new BAlert("Error", "Failed to delete the file.", "OK");
            alert->Go();
        }
    }
}
