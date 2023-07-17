#include <iostream>
#include <string>
#include <chrono>
#include <ctime>
#include <thread>
#include <mutex>
#include <fstream>
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <QtWidgets/QApplication>
#include <QtWidgets/QWidget>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QPlainTextEdit>
#include <QtCore/QTimer>
#include <QtCore/Qtime>
#include <QtWidgets/QMessageBox>
#include <xlnt/xlnt.hpp> // Include the XLNT header

// Required for JSON parsing
using json = nlohmann::json;

// For convenience
using namespace std;
using namespace xlnt;

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

class VirusTotalChecker {
public:
    VirusTotalChecker(const std::string& api_key, const std::string& sha256_hash,
                      const std::string& filename, QPlainTextEdit* console_output)
        : api_key(api_key),
          sha256_hash(sha256_hash),
          url("https://www.virustotal.com/vtapi/v2/file/report?apikey=" + api_key + "&resource=" + sha256_hash),
          filename(filename),
          console_output(console_output) {}

    void check_virustotal() {
        // Send API request
        CURL* curl = curl_easy_init();
        std::string read_buffer;

        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            CURLcode res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);

            // Check if the request was successful
            if (res == CURLE_OK) {
                // Parse JSON
                auto response_json = json::parse(read_buffer);

                // Write JSON to Excel file
                xlnt::workbook wb;
                xlnt::worksheet ws = wb.active_sheet();

                int row = 1;
                for (const auto& item : response_json.items()) {
                    ws.cell(xlnt::cell_reference("A", row)).value(item.key());
                    ws.cell(xlnt::cell_reference("B", row)).value(item.value().dump());
                    row++;
                }

                wb.save(filename);

                // Print success message
                console_output->appendPlainText(QString::fromStdString("Report saved to " + filename + "\n"));
            } else {
                // Print error message
                console_output->appendPlainText(QString::fromStdString("Error: " + std::to_string(res) + "\n"));
            }
        }
    }

private:
    std::string api_key;
    std::string sha256_hash;
    std::string url;
    std::string filename;
    QPlainTextEdit* console_output;
};

class App : public QWidget {
    Q_OBJECT
public:
    App(QWidget* parent = nullptr)
        : QWidget(parent),
          api_key_label(new QLabel("API Key:", this)),
          api_key_entry(new QLineEdit(this)),
          sha256_hash_label(new QLabel("SHA-256 Hash:", this)),
          sha256_hash_entry(new QLineEdit(this)),
          filename_label(new QLabel("Filename:", this)),
          filename_entry(new QLineEdit(this)),
          time_label(new QLabel("Schedule Time (HH:MM):", this)),
          time_entry(new QLineEdit(this)),
          check_button(new QPushButton("Check VirusTotal", this)),
          start_button(new QPushButton("Start Schedule", this)),
          stop_button(new QPushButton("Stop Schedule", this)),
          console_window(new QPlainTextEdit(this)),
          schedule_running(false),
          schedule_timer(new QTimer(this)) {
        // Set up the layout
        QGridLayout* layout = new QGridLayout(this);
        layout->addWidget(api_key_label, 0, 0);
        layout->addWidget(api_key_entry, 0, 1);
        layout->addWidget(sha256_hash_label, 1, 0);
        layout->addWidget(sha256_hash_entry, 1, 1);
        layout->addWidget(filename_label, 2, 0);
        layout->addWidget(filename_entry, 2, 1);
        layout->addWidget(time_label, 3, 0);
        layout->addWidget(time_entry, 3, 1);
        layout->addWidget(check_button, 4, 1);
        layout->addWidget(start_button, 5, 1);
        layout->addWidget(stop_button, 6, 1);
        layout->addWidget(console_window, 7, 0, 1, 2);

        stop_button->setEnabled(false);

        connect(check_button, &QPushButton::clicked, this, &App::check_virustotal);
        connect(start_button, &QPushButton::clicked, this, &App::start_schedule);
        connect(stop_button, &QPushButton::clicked, this, &App::stop_schedule);
        connect(schedule_timer, &QTimer::timeout, this, &App::run_schedule);
    }

public slots:
    void check_virustotal() {
        std::string api_key = api_key_entry->text().toStdString();
        std::string sha256_hash = sha256_hash_entry->text().toStdString();
        std::string filename = filename_entry->text().toStdString();

        VirusTotalChecker vt_checker(api_key, sha256_hash, filename, console_window);
        vt_checker.check_virustotal();
    }

    void start_schedule() {
        // Get schedule time from entry
        QTime schedule_time = QTime::fromString(time_entry->text(), "HH:mm");

        // Check if time is valid
        if (!schedule_time.isValid()) {
            QMessageBox::critical(this, "Invalid Time", "Please enter a valid time in HH:MM format");
            return;
        }

        // Calculate the interval to the next scheduled time
        int interval = QTime::currentTime().msecsTo(schedule_time);
        if (interval <= 0) {
            interval += 24 * 60 * 60 * 1000;  // Add 24 hours if the time has already passed
        }

        // Start the schedule timer
        schedule_timer->start(interval);

        // Update the console window
        console_window->appendPlainText("Schedule started\n");

        // Enable/disable buttons
        start_button->setEnabled(false);
        stop_button->setEnabled(true);
    }

    void run_schedule() {
        check_virustotal();

        // Reset the timer to run every 24 hours
        schedule_timer->setInterval(24 * 60 * 60 * 1000);
    }

    void stop_schedule() {
        // Stop the timer
        schedule_timer->stop();

        // Update the console window
        console_window->appendPlainText("Schedule stopped\n");

        // Enable/disable buttons
        start_button->setEnabled(true);
        stop_button->setEnabled(false);
    }

private:
    QLabel* api_key_label;
    QLineEdit* api_key_entry;
    QLabel* sha256_hash_label;
    QLineEdit* sha256_hash_entry;
    QLabel* filename_label;
    QLineEdit* filename_entry;
    QLabel* time_label;
    QLineEdit* time_entry;
    QPushButton* check_button;
    QPushButton* start_button;
    QPushButton* stop_button;
    QPlainTextEdit* console_window;
    bool schedule_running;
    QTimer* schedule_timer;
};

int main(int argc, char* argv[]) {
    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Initialize Qt Application
    QApplication app(argc, argv);

    // Create the main window
    App mainWindow;
    mainWindow.show();

    // Execute the application
    int result = app.exec();

    // Cleanup CURL
    curl_global_cleanup();

    return result;
}
#include "ThreatScraper.moc"