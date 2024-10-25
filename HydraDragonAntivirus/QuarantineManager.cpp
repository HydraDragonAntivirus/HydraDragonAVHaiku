#include "QuarantineManager.h"
#include <LayoutBuilder.h>
#include <Alert.h>
#include <File.h>
#include <Directory.h>
#include <String.h>
#include <Path.h>
#include <FindDirectory.h>
#include <filesystem>
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
    BButton* restoreAllButton = new BButton("restoreAllButton", "Restore All", new BMessage('rall'));
    BButton* deleteAllButton = new BButton("deleteAllButton", "Delete All", new BMessage('dall'));

    BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
        .Add(fListView)
        .AddGroup(B_HORIZONTAL)
            .Add(restoreButton)
            .Add(deleteButton)
            .Add(restoreAllButton)
            .Add(deleteAllButton)
        .End()
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
    case 'rall':
        RestoreAllFiles();
        break;
    case 'dall':
        DeleteAllFiles();
        break;
    default:
        BWindow::MessageReceived(message);
        break;
    }
}

void QuarantineManager::RestoreSelectedFile() {
    int32 selectedIndex = fListView->CurrentSelection();
    if (selectedIndex >= 0) {
        std::string filePath = quarantinedFiles[selectedIndex];
        
        BPath quarantinePath;
        find_directory(B_USER_SETTINGS_DIRECTORY, &quarantinePath);
        quarantinePath.Append("HydraDragonAntivirus/Quarantine");
        
        BPath restoredFilePath(quarantinePath.Path());
        restoredFilePath.Append(std::filesystem::path(filePath).filename().string().c_str());

        try {
            std::filesystem::rename(restoredFilePath.Path(), filePath);
            BAlert* alert = new BAlert("Restored", "File restored successfully.", "OK");
            alert->Go();
            fListView->RemoveItem(selectedIndex);
            quarantinedFiles.erase(quarantinedFiles.begin() + selectedIndex);
        } catch (const std::filesystem::filesystem_error& e) {
            BAlert* alert = new BAlert("Error", ("Failed to restore the file: " + std::string(e.what())).c_str(), "OK");
            alert->Go();
        }
    }
}

void QuarantineManager::DeleteSelectedFile() {
    int32 selectedIndex = fListView->CurrentSelection();
    if (selectedIndex >= 0) {
        std::string filePath = quarantinedFiles[selectedIndex];

        BPath quarantinePath;
        find_directory(B_USER_SETTINGS_DIRECTORY, &quarantinePath);
        quarantinePath.Append("HydraDragonAntivirus/Quarantine");
        
        BPath fileToDelete(quarantinePath.Path());
        fileToDelete.Append(std::filesystem::path(filePath).filename().string().c_str());

        if (std::filesystem::remove(fileToDelete.Path())) {
            BAlert* alert = new BAlert("Deleted", "File deleted successfully.", "OK");
            alert->Go();
            fListView->RemoveItem(selectedIndex);
            quarantinedFiles.erase(quarantinedFiles.begin() + selectedIndex);
        } else {
            BAlert* alert = new BAlert("Error", "Failed to delete the file.", "OK");
            alert->Go();
        }
    }
}

void QuarantineManager::RestoreAllFiles() {
    BPath quarantinePath;
    find_directory(B_USER_SETTINGS_DIRECTORY, &quarantinePath);
    quarantinePath.Append("HydraDragonAntivirus/Quarantine");

    bool success = true;
    for (const auto& filePath : quarantinedFiles) {
        BPath restoredFilePath(quarantinePath.Path());
        restoredFilePath.Append(std::filesystem::path(filePath).filename().string().c_str());

        try {
            std::filesystem::rename(restoredFilePath.Path(), filePath);
        } catch (const std::filesystem::filesystem_error&) {
            success = false;
        }
    }
    BAlert* alert = new BAlert("Restore All", success ? "All files restored successfully." : "Some files could not be restored.", "OK");
    alert->Go();

    fListView->MakeEmpty();
    quarantinedFiles.clear();
}

void QuarantineManager::DeleteAllFiles() {
    BPath quarantinePath;
    find_directory(B_USER_SETTINGS_DIRECTORY, &quarantinePath);
    quarantinePath.Append("HydraDragonAntivirus/Quarantine");

    bool success = true;
    for (const auto& filePath : quarantinedFiles) {
        BPath fileToDelete(quarantinePath.Path());
        fileToDelete.Append(std::filesystem::path(filePath).filename().string().c_str());

        if (!std::filesystem::remove(fileToDelete.Path())) {
            success = false;
        }
    }
    BAlert* alert = new BAlert("Delete All", success ? "All files deleted successfully." : "Some files could not be deleted.", "OK");
    alert->Go();

    fListView->MakeEmpty();
    quarantinedFiles.clear();
}
