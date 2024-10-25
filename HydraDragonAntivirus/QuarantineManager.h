#ifndef QUARANTINEMANAGER_H
#define QUARANTINEMANAGER_H

#include <Window.h>
#include <View.h>
#include <TextView.h>
#include <ListView.h>
#include <Button.h>
#include <FilePanel.h>
#include <string>
#include <vector>

class QuarantineManager : public BWindow {
public:
    QuarantineManager();
    virtual void MessageReceived(BMessage* message) override;

private:
    void LoadQuarantinedFiles();
    void RestoreSelectedFile();
    void DeleteSelectedFile();

    BListView* fListView;
    std::vector<std::string> quarantinedFiles; // Vector to store file paths
};

#endif // QUARANTINEMANAGER_H
