export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "13.0.4"
  }
  public: {
    Tables: {
      ai_algorithms: {
        Row: {
          algorithm_name: string
          algorithm_version: string | null
          deployed_at: string | null
          description: string | null
          id: number
          is_active: boolean | null
          model_data: Json | null
          performance_metrics: Json | null
          training_metrics: Json | null
          validation_results: Json | null
        }
        Insert: {
          algorithm_name: string
          algorithm_version?: string | null
          deployed_at?: string | null
          description?: string | null
          id?: number
          is_active?: boolean | null
          model_data?: Json | null
          performance_metrics?: Json | null
          training_metrics?: Json | null
          validation_results?: Json | null
        }
        Update: {
          algorithm_name?: string
          algorithm_version?: string | null
          deployed_at?: string | null
          description?: string | null
          id?: number
          is_active?: boolean | null
          model_data?: Json | null
          performance_metrics?: Json | null
          training_metrics?: Json | null
          validation_results?: Json | null
        }
        Relationships: []
      }
      ai_injury_predictions: {
        Row: {
          athlete_id: string
          body_parts_at_risk: Json | null
          confidence_level: number | null
          created_at: string | null
          id: number
          prediction_date: string
          prediction_model: string | null
          recommended_actions: Json | null
          risk_factors: Json | null
          risk_score: number | null
          updated_at: string | null
        }
        Insert: {
          athlete_id: string
          body_parts_at_risk?: Json | null
          confidence_level?: number | null
          created_at?: string | null
          id?: number
          prediction_date: string
          prediction_model?: string | null
          recommended_actions?: Json | null
          risk_factors?: Json | null
          risk_score?: number | null
          updated_at?: string | null
        }
        Update: {
          athlete_id?: string
          body_parts_at_risk?: Json | null
          confidence_level?: number | null
          created_at?: string | null
          id?: number
          prediction_date?: string
          prediction_model?: string | null
          recommended_actions?: Json | null
          risk_factors?: Json | null
          risk_score?: number | null
          updated_at?: string | null
        }
        Relationships: []
      }
      appointments: {
        Row: {
          appointment_date: string
          appointment_type: string
          created_at: string | null
          duration_minutes: number | null
          id: string
          notes: string | null
          player_id: string
          reminder_sent: boolean | null
          staff_id: string
          status: string | null
          updated_at: string | null
        }
        Insert: {
          appointment_date: string
          appointment_type: string
          created_at?: string | null
          duration_minutes?: number | null
          id?: string
          notes?: string | null
          player_id: string
          reminder_sent?: boolean | null
          staff_id: string
          status?: string | null
          updated_at?: string | null
        }
        Update: {
          appointment_date?: string
          appointment_type?: string
          created_at?: string | null
          duration_minutes?: number | null
          id?: string
          notes?: string | null
          player_id?: string
          reminder_sent?: boolean | null
          staff_id?: string
          status?: string | null
          updated_at?: string | null
        }
        Relationships: []
      }
      assessments: {
        Row: {
          assessment_date: string
          assessment_type: string
          assessor_id: string
          athlete_id: string
          created_at: string | null
          data: Json
          flags: Json | null
          id: string
          next_assessment_date: string | null
          notes: string | null
          scores: Json | null
          status: string
          updated_at: string | null
        }
        Insert: {
          assessment_date?: string
          assessment_type: string
          assessor_id: string
          athlete_id: string
          created_at?: string | null
          data?: Json
          flags?: Json | null
          id?: string
          next_assessment_date?: string | null
          notes?: string | null
          scores?: Json | null
          status?: string
          updated_at?: string | null
        }
        Update: {
          assessment_date?: string
          assessment_type?: string
          assessor_id?: string
          athlete_id?: string
          created_at?: string | null
          data?: Json
          flags?: Json | null
          id?: string
          next_assessment_date?: string | null
          notes?: string | null
          scores?: Json | null
          status?: string
          updated_at?: string | null
        }
        Relationships: []
      }
      athletes: {
        Row: {
          allergies: Json | null
          bmi: number | null
          created_at: string | null
          dominant_foot: string | null
          dominant_hand: string | null
          family_history: Json | null
          height: number | null
          id: string
          immunizations: Json | null
          level: string
          medical_history: Json | null
          medications: Json | null
          profile_id: string
          sport: string
          training_hours_per_week: number | null
          updated_at: string | null
          weight: number | null
          years_experience: number | null
        }
        Insert: {
          allergies?: Json | null
          bmi?: number | null
          created_at?: string | null
          dominant_foot?: string | null
          dominant_hand?: string | null
          family_history?: Json | null
          height?: number | null
          id?: string
          immunizations?: Json | null
          level?: string
          medical_history?: Json | null
          medications?: Json | null
          profile_id: string
          sport: string
          training_hours_per_week?: number | null
          updated_at?: string | null
          weight?: number | null
          years_experience?: number | null
        }
        Update: {
          allergies?: Json | null
          bmi?: number | null
          created_at?: string | null
          dominant_foot?: string | null
          dominant_hand?: string | null
          family_history?: Json | null
          height?: number | null
          id?: string
          immunizations?: Json | null
          level?: string
          medical_history?: Json | null
          medications?: Json | null
          profile_id?: string
          sport?: string
          training_hours_per_week?: number | null
          updated_at?: string | null
          weight?: number | null
          years_experience?: number | null
        }
        Relationships: []
      }
      audit_logs: {
        Row: {
          action: string
          created_at: string | null
          details: Json | null
          id: string
          ip_address: unknown | null
          record_id: string | null
          session_id: string | null
          table_name: string
          user_agent: string | null
          user_id: string | null
        }
        Insert: {
          action: string
          created_at?: string | null
          details?: Json | null
          id?: string
          ip_address?: unknown | null
          record_id?: string | null
          session_id?: string | null
          table_name: string
          user_agent?: string | null
          user_id?: string | null
        }
        Update: {
          action?: string
          created_at?: string | null
          details?: Json | null
          id?: string
          ip_address?: unknown | null
          record_id?: string | null
          session_id?: string | null
          table_name?: string
          user_agent?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      cmj_tests: {
        Row: {
          balance_left_percent: number | null
          balance_right_percent: number | null
          created_at: string | null
          flight_time_ms: number | null
          ground_contact_time_ms: number | null
          id: string
          jump_height_cm: number | null
          notes: string | null
          peak_force_n: number | null
          player_id: string
          power_watts: number | null
          rsi_score: number | null
          test_date: string
          tested_by: string | null
        }
        Insert: {
          balance_left_percent?: number | null
          balance_right_percent?: number | null
          created_at?: string | null
          flight_time_ms?: number | null
          ground_contact_time_ms?: number | null
          id?: string
          jump_height_cm?: number | null
          notes?: string | null
          peak_force_n?: number | null
          player_id: string
          power_watts?: number | null
          rsi_score?: number | null
          test_date: string
          tested_by?: string | null
        }
        Update: {
          balance_left_percent?: number | null
          balance_right_percent?: number | null
          created_at?: string | null
          flight_time_ms?: number | null
          ground_contact_time_ms?: number | null
          id?: string
          jump_height_cm?: number | null
          notes?: string | null
          peak_force_n?: number | null
          player_id?: string
          power_watts?: number | null
          rsi_score?: number | null
          test_date?: string
          tested_by?: string | null
        }
        Relationships: []
      }
      compliance_consents: {
        Row: {
          consent_type: string
          consent_version: string | null
          data_categories: Json | null
          expires_at: string | null
          granted_at: string | null
          id: number
          ip_address: unknown | null
          legal_basis: string | null
          processing_purposes: Json | null
          user_id: string
          withdrawn_at: string | null
        }
        Insert: {
          consent_type: string
          consent_version?: string | null
          data_categories?: Json | null
          expires_at?: string | null
          granted_at?: string | null
          id?: number
          ip_address?: unknown | null
          legal_basis?: string | null
          processing_purposes?: Json | null
          user_id: string
          withdrawn_at?: string | null
        }
        Update: {
          consent_type?: string
          consent_version?: string | null
          data_categories?: Json | null
          expires_at?: string | null
          granted_at?: string | null
          id?: number
          ip_address?: unknown | null
          legal_basis?: string | null
          processing_purposes?: Json | null
          user_id?: string
          withdrawn_at?: string | null
        }
        Relationships: []
      }
      consent_records: {
        Row: {
          athlete_id: string
          consent_date: string | null
          consent_text: string
          consent_type: string
          consent_version: string | null
          created_at: string | null
          digital_signature: string | null
          id: string
          ip_address: unknown | null
          is_consented: boolean
          parent_consent_given: boolean | null
          parent_consent_required: boolean | null
          updated_at: string | null
          withdrawal_date: string | null
          witness_name: string | null
        }
        Insert: {
          athlete_id: string
          consent_date?: string | null
          consent_text: string
          consent_type: string
          consent_version?: string | null
          created_at?: string | null
          digital_signature?: string | null
          id?: string
          ip_address?: unknown | null
          is_consented?: boolean
          parent_consent_given?: boolean | null
          parent_consent_required?: boolean | null
          updated_at?: string | null
          withdrawal_date?: string | null
          witness_name?: string | null
        }
        Update: {
          athlete_id?: string
          consent_date?: string | null
          consent_text?: string
          consent_type?: string
          consent_version?: string | null
          created_at?: string | null
          digital_signature?: string | null
          id?: string
          ip_address?: unknown | null
          is_consented?: boolean
          parent_consent_given?: boolean | null
          parent_consent_required?: boolean | null
          updated_at?: string | null
          withdrawal_date?: string | null
          witness_name?: string | null
        }
        Relationships: []
      }
      crt6_assessments: {
        Row: {
          assessment_date: string
          assessment_id: string
          assessor_name: string
          athlete_name: string
          created_at: string | null
          id: string
          immediate_actions_taken: Json | null
          initial_symptoms: Json | null
          mechanism_of_injury: string | null
          medical_attention_required: boolean | null
          observable_signs: Json | null
          recommendations: string | null
          red_flags: Json | null
          return_to_play_same_day: boolean | null
          updated_at: string | null
          witness_observations: string | null
        }
        Insert: {
          assessment_date: string
          assessment_id: string
          assessor_name: string
          athlete_name: string
          created_at?: string | null
          id?: string
          immediate_actions_taken?: Json | null
          initial_symptoms?: Json | null
          mechanism_of_injury?: string | null
          medical_attention_required?: boolean | null
          observable_signs?: Json | null
          recommendations?: string | null
          red_flags?: Json | null
          return_to_play_same_day?: boolean | null
          updated_at?: string | null
          witness_observations?: string | null
        }
        Update: {
          assessment_date?: string
          assessment_id?: string
          assessor_name?: string
          athlete_name?: string
          created_at?: string | null
          id?: string
          immediate_actions_taken?: Json | null
          initial_symptoms?: Json | null
          mechanism_of_injury?: string | null
          medical_attention_required?: boolean | null
          observable_signs?: Json | null
          recommendations?: string | null
          red_flags?: Json | null
          return_to_play_same_day?: boolean | null
          updated_at?: string | null
          witness_observations?: string | null
        }
        Relationships: []
      }
      device_data_streams: {
        Row: {
          anomaly_flags: Json | null
          athlete_id: string
          data_type: string
          device_id: number
          id: number
          processed_data: Json | null
          quality_score: number | null
          raw_data: Json | null
          session_id: string | null
          timestamp: string | null
        }
        Insert: {
          anomaly_flags?: Json | null
          athlete_id: string
          data_type: string
          device_id: number
          id?: number
          processed_data?: Json | null
          quality_score?: number | null
          raw_data?: Json | null
          session_id?: string | null
          timestamp?: string | null
        }
        Update: {
          anomaly_flags?: Json | null
          athlete_id?: string
          data_type?: string
          device_id?: number
          id?: number
          processed_data?: Json | null
          quality_score?: number | null
          raw_data?: Json | null
          session_id?: string | null
          timestamp?: string | null
        }
        Relationships: []
      }
      digital_signatures: {
        Row: {
          assessment_id: string
          certificate_data: Json | null
          id: number
          legal_status: string | null
          signature_data: string
          signature_type: string | null
          signed_at: string | null
          signer_id: string
          validity_verified: boolean | null
          verification_hash: string | null
        }
        Insert: {
          assessment_id: string
          certificate_data?: Json | null
          id?: number
          legal_status?: string | null
          signature_data: string
          signature_type?: string | null
          signed_at?: string | null
          signer_id: string
          validity_verified?: boolean | null
          verification_hash?: string | null
        }
        Update: {
          assessment_id?: string
          certificate_data?: Json | null
          id?: number
          legal_status?: string | null
          signature_data?: string
          signature_type?: string | null
          signed_at?: string | null
          signer_id?: string
          validity_verified?: boolean | null
          verification_hash?: string | null
        }
        Relationships: []
      }
      document_ocr_results: {
        Row: {
          confidence_score: number | null
          created_at: string | null
          extracted_fields: Json | null
          id: string
          ocr_text: string | null
          original_file_name: string | null
          processed_by: string | null
          reviewed_by: string | null
          scanned_document_id: string | null
          updated_at: string | null
          validation_notes: string | null
          validation_status: string | null
        }
        Insert: {
          confidence_score?: number | null
          created_at?: string | null
          extracted_fields?: Json | null
          id?: string
          ocr_text?: string | null
          original_file_name?: string | null
          processed_by?: string | null
          reviewed_by?: string | null
          scanned_document_id?: string | null
          updated_at?: string | null
          validation_notes?: string | null
          validation_status?: string | null
        }
        Update: {
          confidence_score?: number | null
          created_at?: string | null
          extracted_fields?: Json | null
          id?: string
          ocr_text?: string | null
          original_file_name?: string | null
          processed_by?: string | null
          reviewed_by?: string | null
          scanned_document_id?: string | null
          updated_at?: string | null
          validation_notes?: string | null
          validation_status?: string | null
        }
        Relationships: []
      }
      injury_reports: {
        Row: {
          anatomical_location: string | null
          assessment_id: string
          athlete_id: string
          body_region: string | null
          created_at: string | null
          diagnosis: string | null
          emergency_transport: boolean | null
          expected_recovery_time: string | null
          follow_up_required: boolean | null
          icd10_code: string | null
          id: string
          imaging_ordered: Json | null
          imaging_results: Json | null
          immediate_care_provided: string | null
          incident_date: string
          injury_location: string
          injury_type: string
          mechanism_of_injury: string
          physician_notes: string | null
          report_date: string
          reporter_id: string
          return_to_play_estimate: string | null
          severity_level: string | null
          tissue_type: string | null
          treatment_plan: Json | null
          updated_at: string | null
        }
        Insert: {
          anatomical_location?: string | null
          assessment_id: string
          athlete_id: string
          body_region?: string | null
          created_at?: string | null
          diagnosis?: string | null
          emergency_transport?: boolean | null
          expected_recovery_time?: string | null
          follow_up_required?: boolean | null
          icd10_code?: string | null
          id?: string
          imaging_ordered?: Json | null
          imaging_results?: Json | null
          immediate_care_provided?: string | null
          incident_date: string
          injury_location: string
          injury_type: string
          mechanism_of_injury: string
          physician_notes?: string | null
          report_date?: string
          reporter_id: string
          return_to_play_estimate?: string | null
          severity_level?: string | null
          tissue_type?: string | null
          treatment_plan?: Json | null
          updated_at?: string | null
        }
        Update: {
          anatomical_location?: string | null
          assessment_id?: string
          athlete_id?: string
          body_region?: string | null
          created_at?: string | null
          diagnosis?: string | null
          emergency_transport?: boolean | null
          expected_recovery_time?: string | null
          follow_up_required?: boolean | null
          icd10_code?: string | null
          id?: string
          imaging_ordered?: Json | null
          imaging_results?: Json | null
          immediate_care_provided?: string | null
          incident_date?: string
          injury_location?: string
          injury_type?: string
          mechanism_of_injury?: string
          physician_notes?: string | null
          report_date?: string
          reporter_id?: string
          return_to_play_estimate?: string | null
          severity_level?: string | null
          tissue_type?: string | null
          treatment_plan?: Json | null
          updated_at?: string | null
        }
        Relationships: []
      }
      injury_statistics: {
        Row: {
          body_region: string | null
          cause_category: string | null
          created_at: string | null
          created_by: string | null
          days_out: number | null
          id: string
          injury_date: string | null
          injury_type: string | null
          player_id: string | null
          prevention_measures: string | null
          recovery_date: string | null
          severity_level: string | null
        }
        Insert: {
          body_region?: string | null
          cause_category?: string | null
          created_at?: string | null
          created_by?: string | null
          days_out?: number | null
          id?: string
          injury_date?: string | null
          injury_type?: string | null
          player_id?: string | null
          prevention_measures?: string | null
          recovery_date?: string | null
          severity_level?: string | null
        }
        Update: {
          body_region?: string | null
          cause_category?: string | null
          created_at?: string | null
          created_by?: string | null
          days_out?: number | null
          id?: string
          injury_date?: string | null
          injury_type?: string | null
          player_id?: string | null
          prevention_measures?: string | null
          recovery_date?: string | null
          severity_level?: string | null
        }
        Relationships: []
      }
      intelligent_notifications: {
        Row: {
          acknowledged_at: string | null
          acknowledged_by: string | null
          alert_type: string
          created_at: string | null
          data: Json | null
          expires_at: string | null
          id: number
          is_read: boolean | null
          message: string | null
          severity: string
          title: string | null
          user_id: string
        }
        Insert: {
          acknowledged_at?: string | null
          acknowledged_by?: string | null
          alert_type: string
          created_at?: string | null
          data?: Json | null
          expires_at?: string | null
          id?: number
          is_read?: boolean | null
          message?: string | null
          severity: string
          title?: string | null
          user_id: string
        }
        Update: {
          acknowledged_at?: string | null
          acknowledged_by?: string | null
          alert_type?: string
          created_at?: string | null
          data?: Json | null
          expires_at?: string | null
          id?: number
          is_read?: boolean | null
          message?: string | null
          severity?: string
          title?: string | null
          user_id?: string
        }
        Relationships: []
      }
      medical_devices: {
        Row: {
          api_endpoint: string | null
          authentication_config: Json | null
          created_at: string | null
          data_mapping: Json | null
          device_name: string
          device_type: string
          id: number
          is_active: boolean | null
          manufacturer: string | null
          model: string | null
          serial_number: string | null
          updated_at: string | null
        }
        Insert: {
          api_endpoint?: string | null
          authentication_config?: Json | null
          created_at?: string | null
          data_mapping?: Json | null
          device_name: string
          device_type: string
          id?: number
          is_active?: boolean | null
          manufacturer?: string | null
          model?: string | null
          serial_number?: string | null
          updated_at?: string | null
        }
        Update: {
          api_endpoint?: string | null
          authentication_config?: Json | null
          created_at?: string | null
          data_mapping?: Json | null
          device_name?: string
          device_type?: string
          id?: number
          is_active?: boolean | null
          manufacturer?: string | null
          model?: string | null
          serial_number?: string | null
          updated_at?: string | null
        }
        Relationships: []
      }
      medical_documents: {
        Row: {
          access_level: string | null
          athlete_id: string
          created_at: string | null
          description: string | null
          document_type: string
          encryption_key_id: string | null
          file_name: string
          file_size: number | null
          id: string
          is_deleted: boolean | null
          is_encrypted: boolean | null
          mime_type: string | null
          storage_path: string
          tags: Json | null
          updated_at: string | null
          uploader_id: string
        }
        Insert: {
          access_level?: string | null
          athlete_id: string
          created_at?: string | null
          description?: string | null
          document_type: string
          encryption_key_id?: string | null
          file_name: string
          file_size?: number | null
          id?: string
          is_deleted?: boolean | null
          is_encrypted?: boolean | null
          mime_type?: string | null
          storage_path: string
          tags?: Json | null
          updated_at?: string | null
          uploader_id: string
        }
        Update: {
          access_level?: string | null
          athlete_id?: string
          created_at?: string | null
          description?: string | null
          document_type?: string
          encryption_key_id?: string | null
          file_name?: string
          file_size?: number | null
          id?: string
          is_deleted?: boolean | null
          is_encrypted?: boolean | null
          mime_type?: string | null
          storage_path?: string
          tags?: Json | null
          updated_at?: string | null
          uploader_id?: string
        }
        Relationships: []
      }
      medical_treatments: {
        Row: {
          created_at: string | null
          created_by: string | null
          diagnosis: string | null
          follow_up_date: string | null
          hospital_or_practice: string | null
          icd10_code: string | null
          id: string
          player_id: string
          prognosis: string | null
          therapy_recommendations: string | null
          treating_doctor: string | null
          treatment_date: string
          treatment_measures: string | null
          treatment_notes: string | null
          updated_at: string | null
        }
        Insert: {
          created_at?: string | null
          created_by?: string | null
          diagnosis?: string | null
          follow_up_date?: string | null
          hospital_or_practice?: string | null
          icd10_code?: string | null
          id?: string
          player_id: string
          prognosis?: string | null
          therapy_recommendations?: string | null
          treating_doctor?: string | null
          treatment_date: string
          treatment_measures?: string | null
          treatment_notes?: string | null
          updated_at?: string | null
        }
        Update: {
          created_at?: string | null
          created_by?: string | null
          diagnosis?: string | null
          follow_up_date?: string | null
          hospital_or_practice?: string | null
          icd10_code?: string | null
          id?: string
          player_id?: string
          prognosis?: string | null
          therapy_recommendations?: string | null
          treating_doctor?: string | null
          treatment_date?: string
          treatment_measures?: string | null
          treatment_notes?: string | null
          updated_at?: string | null
        }
        Relationships: []
      }
      notifications: {
        Row: {
          action_required: boolean | null
          action_taken: boolean | null
          created_at: string | null
          expires_at: string | null
          id: string
          is_read: boolean | null
          message: string
          metadata: Json | null
          notification_type: string
          priority: string | null
          read_at: string | null
          recipient_id: string
          related_id: string | null
          related_table: string | null
          sender_id: string | null
          title: string
        }
        Insert: {
          action_required?: boolean | null
          action_taken?: boolean | null
          created_at?: string | null
          expires_at?: string | null
          id?: string
          is_read?: boolean | null
          message: string
          metadata?: Json | null
          notification_type: string
          priority?: string | null
          read_at?: string | null
          recipient_id: string
          related_id?: string | null
          related_table?: string | null
          sender_id?: string | null
          title: string
        }
        Update: {
          action_required?: boolean | null
          action_taken?: boolean | null
          created_at?: string | null
          expires_at?: string | null
          id?: string
          is_read?: boolean | null
          message?: string
          metadata?: Json | null
          notification_type?: string
          priority?: string | null
          read_at?: string | null
          recipient_id?: string
          related_id?: string | null
          related_table?: string | null
          sender_id?: string | null
          title?: string
        }
        Relationships: []
      }
      ocr_jobs: {
        Row: {
          confidence_score: number | null
          created_at: string | null
          created_by: string | null
          document_type: string
          extracted_data: Json | null
          file_path: string
          id: string
          ocr_status: string | null
          original_filename: string
          player_id: string
          processing_time: number | null
          raw_text: string | null
          updated_at: string | null
        }
        Insert: {
          confidence_score?: number | null
          created_at?: string | null
          created_by?: string | null
          document_type: string
          extracted_data?: Json | null
          file_path: string
          id?: string
          ocr_status?: string | null
          original_filename: string
          player_id: string
          processing_time?: number | null
          raw_text?: string | null
          updated_at?: string | null
        }
        Update: {
          confidence_score?: number | null
          created_at?: string | null
          created_by?: string | null
          document_type?: string
          extracted_data?: Json | null
          file_path?: string
          id?: string
          ocr_status?: string | null
          original_filename?: string
          player_id?: string
          processing_time?: number | null
          raw_text?: string | null
          updated_at?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "ocr_jobs_created_by_fkey"
            columns: ["created_by"]
            isOneToOne: false
            referencedRelation: "profiles"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "ocr_jobs_player_id_fkey"
            columns: ["player_id"]
            isOneToOne: false
            referencedRelation: "players"
            referencedColumns: ["id"]
          },
        ]
      }
      ostrc_assessments: {
        Row: {
          additional_comments: string | null
          assessment_date: string
          assessment_id: string
          athlete_id: string
          created_at: string | null
          id: string
          injury_location: string | null
          injury_type: string | null
          participation_reduction: number
          performance_reduction: number
          symptom_severity: number
          time_loss: number
          total_score: number | null
          updated_at: string | null
          week_number: number
        }
        Insert: {
          additional_comments?: string | null
          assessment_date: string
          assessment_id: string
          athlete_id: string
          created_at?: string | null
          id?: string
          injury_location?: string | null
          injury_type?: string | null
          participation_reduction: number
          performance_reduction: number
          symptom_severity: number
          time_loss: number
          total_score?: number | null
          updated_at?: string | null
          week_number: number
        }
        Update: {
          additional_comments?: string | null
          assessment_date?: string
          assessment_id?: string
          athlete_id?: string
          created_at?: string | null
          id?: string
          injury_location?: string | null
          injury_type?: string | null
          participation_reduction?: number
          performance_reduction?: number
          symptom_severity?: number
          time_loss?: number
          total_score?: number | null
          updated_at?: string | null
          week_number?: number
        }
        Relationships: []
      }
      pcma_assessments: {
        Row: {
          allergies: Json | null
          assessment_date: string
          assessment_id: string
          athlete_name: string
          blood_pressure: string | null
          bmi: number | null
          clearance_decision: string
          conditions_recommendations: string | null
          created_at: string | null
          date_of_birth: string
          dental_status: string | null
          echo_results: Json | null
          family_history: Json | null
          height: number | null
          id: string
          immunization_status: Json | null
          infections: Json | null
          lab_results: Json | null
          medications: Json | null
          muscle_joint_status: Json | null
          physician_name: string
          physician_signature: string | null
          pre_conditions: Json | null
          previous_surgeries: Json | null
          pulse: number | null
          resting_ecg: Json | null
          team: string
          updated_at: string | null
          vision_hearing_test: Json | null
          weight: number | null
        }
        Insert: {
          allergies?: Json | null
          assessment_date: string
          assessment_id: string
          athlete_name: string
          blood_pressure?: string | null
          bmi?: number | null
          clearance_decision: string
          conditions_recommendations?: string | null
          created_at?: string | null
          date_of_birth: string
          dental_status?: string | null
          echo_results?: Json | null
          family_history?: Json | null
          height?: number | null
          id?: string
          immunization_status?: Json | null
          infections?: Json | null
          lab_results?: Json | null
          medications?: Json | null
          muscle_joint_status?: Json | null
          physician_name: string
          physician_signature?: string | null
          pre_conditions?: Json | null
          previous_surgeries?: Json | null
          pulse?: number | null
          resting_ecg?: Json | null
          team: string
          updated_at?: string | null
          vision_hearing_test?: Json | null
          weight?: number | null
        }
        Update: {
          allergies?: Json | null
          assessment_date?: string
          assessment_id?: string
          athlete_name?: string
          blood_pressure?: string | null
          bmi?: number | null
          clearance_decision?: string
          conditions_recommendations?: string | null
          created_at?: string | null
          date_of_birth?: string
          dental_status?: string | null
          echo_results?: Json | null
          family_history?: Json | null
          height?: number | null
          id?: string
          immunization_status?: Json | null
          infections?: Json | null
          lab_results?: Json | null
          medications?: Json | null
          muscle_joint_status?: Json | null
          physician_name?: string
          physician_signature?: string | null
          pre_conditions?: Json | null
          previous_surgeries?: Json | null
          pulse?: number | null
          resting_ecg?: Json | null
          team?: string
          updated_at?: string | null
          vision_hearing_test?: Json | null
          weight?: number | null
        }
        Relationships: []
      }
      performance_assessments: {
        Row: {
          assessed_by: string | null
          assessment_date: string
          assessment_type: string
          created_at: string | null
          follow_up_date: string | null
          id: string
          player_id: string
          recommendations: string | null
          results: Json | null
          risk_score: number | null
        }
        Insert: {
          assessed_by?: string | null
          assessment_date: string
          assessment_type: string
          created_at?: string | null
          follow_up_date?: string | null
          id?: string
          player_id: string
          recommendations?: string | null
          results?: Json | null
          risk_score?: number | null
        }
        Update: {
          assessed_by?: string | null
          assessment_date?: string
          assessment_type?: string
          created_at?: string | null
          follow_up_date?: string | null
          id?: string
          player_id?: string
          recommendations?: string | null
          results?: Json | null
          risk_score?: number | null
        }
        Relationships: []
      }
      performance_metrics: {
        Row: {
          created_at: string | null
          department: string | null
          id: string
          measurement_date: string
          metric_name: string
          metric_unit: string | null
          metric_value: number | null
          notes: string | null
          player_id: string | null
          recorded_by: string | null
        }
        Insert: {
          created_at?: string | null
          department?: string | null
          id?: string
          measurement_date: string
          metric_name: string
          metric_unit?: string | null
          metric_value?: number | null
          notes?: string | null
          player_id?: string | null
          recorded_by?: string | null
        }
        Update: {
          created_at?: string | null
          department?: string | null
          id?: string
          measurement_date?: string
          metric_name?: string
          metric_unit?: string | null
          metric_value?: number | null
          notes?: string | null
          player_id?: string | null
          recorded_by?: string | null
        }
        Relationships: []
      }
      physio_assessments: {
        Row: {
          complaints_in_daily_life: string | null
          complaints_since_when: string | null
          created_at: string | null
          current_complaints: string | null
          current_occupation: string | null
          date_of_assessment: string
          diagnosis: string | null
          frequency_of_complaints: string | null
          id: string
          inspection_findings: string | null
          medications: string | null
          pain_description: string | null
          pain_intensity: number | null
          palpation_findings: string | null
          player_id: string
          previous_therapies: string | null
          previous_treatments: string | null
          recreational_activities: string | null
          relieved_by: string | null
          secondary_diagnosis: string | null
          social_history: string | null
          specific_findings: string | null
          therapist_id: string | null
          therapy_goals: string | null
          triggered_by: string | null
          updated_at: string | null
        }
        Insert: {
          complaints_in_daily_life?: string | null
          complaints_since_when?: string | null
          created_at?: string | null
          current_complaints?: string | null
          current_occupation?: string | null
          date_of_assessment: string
          diagnosis?: string | null
          frequency_of_complaints?: string | null
          id?: string
          inspection_findings?: string | null
          medications?: string | null
          pain_description?: string | null
          pain_intensity?: number | null
          palpation_findings?: string | null
          player_id: string
          previous_therapies?: string | null
          previous_treatments?: string | null
          recreational_activities?: string | null
          relieved_by?: string | null
          secondary_diagnosis?: string | null
          social_history?: string | null
          specific_findings?: string | null
          therapist_id?: string | null
          therapy_goals?: string | null
          triggered_by?: string | null
          updated_at?: string | null
        }
        Update: {
          complaints_in_daily_life?: string | null
          complaints_since_when?: string | null
          created_at?: string | null
          current_complaints?: string | null
          current_occupation?: string | null
          date_of_assessment?: string
          diagnosis?: string | null
          frequency_of_complaints?: string | null
          id?: string
          inspection_findings?: string | null
          medications?: string | null
          pain_description?: string | null
          pain_intensity?: number | null
          palpation_findings?: string | null
          player_id?: string
          previous_therapies?: string | null
          previous_treatments?: string | null
          recreational_activities?: string | null
          relieved_by?: string | null
          secondary_diagnosis?: string | null
          social_history?: string | null
          specific_findings?: string | null
          therapist_id?: string | null
          therapy_goals?: string | null
          triggered_by?: string | null
          updated_at?: string | null
        }
        Relationships: []
      }
      physio_documentation: {
        Row: {
          assessment_id: string
          created_at: string | null
          date: string
          id: string
          notes: string
          therapist_id: string | null
          updated_at: string | null
        }
        Insert: {
          assessment_id: string
          created_at?: string | null
          date: string
          id?: string
          notes: string
          therapist_id?: string | null
          updated_at?: string | null
        }
        Update: {
          assessment_id?: string
          created_at?: string | null
          date?: string
          id?: string
          notes?: string
          therapist_id?: string | null
          updated_at?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "physio_documentation_assessment_id_fkey"
            columns: ["assessment_id"]
            isOneToOne: false
            referencedRelation: "physio_assessments"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "physio_documentation_therapist_id_fkey"
            columns: ["therapist_id"]
            isOneToOne: false
            referencedRelation: "profiles"
            referencedColumns: ["id"]
          },
        ]
      }
      physio_sessions: {
        Row: {
          absence_reason: string | null
          attended: boolean | null
          created_at: string | null
          id: string
          next_steps: string | null
          patient_response: string | null
          physio_assessment_id: string
          session_date: string
          session_notes: string | null
          therapist_id: string | null
          treatment_performed: string | null
        }
        Insert: {
          absence_reason?: string | null
          attended?: boolean | null
          created_at?: string | null
          id?: string
          next_steps?: string | null
          patient_response?: string | null
          physio_assessment_id: string
          session_date: string
          session_notes?: string | null
          therapist_id?: string | null
          treatment_performed?: string | null
        }
        Update: {
          absence_reason?: string | null
          attended?: boolean | null
          created_at?: string | null
          id?: string
          next_steps?: string | null
          patient_response?: string | null
          physio_assessment_id?: string
          session_date?: string
          session_notes?: string | null
          therapist_id?: string | null
          treatment_performed?: string | null
        }
        Relationships: []
      }
      players: {
        Row: {
          created_at: string | null
          date_of_birth: string | null
          emergency_contact: string | null
          emergency_phone: string | null
          first_name: string
          height: number | null
          id: string
          is_active: boolean | null
          jersey_number: number | null
          last_name: string
          position: string | null
          updated_at: string | null
          weight: number | null
        }
        Insert: {
          created_at?: string | null
          date_of_birth?: string | null
          emergency_contact?: string | null
          emergency_phone?: string | null
          first_name: string
          height?: number | null
          id?: string
          is_active?: boolean | null
          jersey_number?: number | null
          last_name: string
          position?: string | null
          updated_at?: string | null
          weight?: number | null
        }
        Update: {
          created_at?: string | null
          date_of_birth?: string | null
          emergency_contact?: string | null
          emergency_phone?: string | null
          first_name?: string
          height?: number | null
          id?: string
          is_active?: boolean | null
          jersey_number?: number | null
          last_name?: string
          position?: string | null
          updated_at?: string | null
          weight?: number | null
        }
        Relationships: []
      }
      profiles: {
        Row: {
          created_at: string | null
          date_of_birth: string | null
          email: string
          emergency_contact_name: string | null
          emergency_contact_phone: string | null
          full_name: string
          id: string
          is_active: boolean | null
          medical_record_number: string | null
          phone: string | null
          position: string | null
          role: string
          team: string | null
          updated_at: string | null
          user_id: string
        }
        Insert: {
          created_at?: string | null
          date_of_birth?: string | null
          email: string
          emergency_contact_name?: string | null
          emergency_contact_phone?: string | null
          full_name: string
          id?: string
          is_active?: boolean | null
          medical_record_number?: string | null
          phone?: string | null
          position?: string | null
          role?: string
          team?: string | null
          updated_at?: string | null
          user_id: string
        }
        Update: {
          created_at?: string | null
          date_of_birth?: string | null
          email?: string
          emergency_contact_name?: string | null
          emergency_contact_phone?: string | null
          full_name?: string
          id?: string
          is_active?: boolean | null
          medical_record_number?: string | null
          phone?: string | null
          position?: string | null
          role?: string
          team?: string | null
          updated_at?: string | null
          user_id?: string
        }
        Relationships: []
      }
      pt_soap_notes: {
        Row: {
          assessment_findings: Json
          assessment_id: string
          athlete_id: string
          created_at: string | null
          homework_exercises: Json | null
          id: string
          interventions_performed: Json | null
          next_appointment: string | null
          objective: Json
          patient_response: string | null
          physiotherapist_id: string
          plan: Json
          progress_rating: number | null
          session_date: string
          session_duration: number | null
          subjective: Json
          treatment_goals: Json | null
          treatment_phase: string | null
          updated_at: string | null
        }
        Insert: {
          assessment_findings?: Json
          assessment_id: string
          athlete_id: string
          created_at?: string | null
          homework_exercises?: Json | null
          id?: string
          interventions_performed?: Json | null
          next_appointment?: string | null
          objective?: Json
          patient_response?: string | null
          physiotherapist_id: string
          plan?: Json
          progress_rating?: number | null
          session_date: string
          session_duration?: number | null
          subjective?: Json
          treatment_goals?: Json | null
          treatment_phase?: string | null
          updated_at?: string | null
        }
        Update: {
          assessment_findings?: Json
          assessment_id?: string
          athlete_id?: string
          created_at?: string | null
          homework_exercises?: Json | null
          id?: string
          interventions_performed?: Json | null
          next_appointment?: string | null
          objective?: Json
          patient_response?: string | null
          physiotherapist_id?: string
          plan?: Json
          progress_rating?: number | null
          session_date?: string
          session_duration?: number | null
          subjective?: Json
          treatment_goals?: Json | null
          treatment_phase?: string | null
          updated_at?: string | null
        }
        Relationships: []
      }
      research_studies: {
        Row: {
          created_at: string | null
          data_collection_protocol: Json | null
          description: string | null
          end_date: string | null
          id: number
          participant_criteria: Json | null
          principal_investigator: string | null
          start_date: string | null
          statistical_methods: Json | null
          status: string | null
          study_name: string
          study_type: string | null
          updated_at: string | null
        }
        Insert: {
          created_at?: string | null
          data_collection_protocol?: Json | null
          description?: string | null
          end_date?: string | null
          id?: number
          participant_criteria?: Json | null
          principal_investigator?: string | null
          start_date?: string | null
          statistical_methods?: Json | null
          status?: string | null
          study_name: string
          study_type?: string | null
          updated_at?: string | null
        }
        Update: {
          created_at?: string | null
          data_collection_protocol?: Json | null
          description?: string | null
          end_date?: string | null
          id?: number
          participant_criteria?: Json | null
          principal_investigator?: string | null
          start_date?: string | null
          statistical_methods?: Json | null
          status?: string | null
          study_name?: string
          study_type?: string | null
          updated_at?: string | null
        }
        Relationships: []
      }
      rtp_protocols: {
        Row: {
          assessment_id: string
          athlete_id: string
          created_at: string | null
          current_stage: number
          final_clearance_date: string | null
          id: string
          injury_id: string | null
          medical_clearances: Json | null
          progression_notes: string | null
          protocol_start_date: string
          protocol_status: string | null
          return_to_competition_date: string | null
          setbacks: Json | null
          stage_0_data: Json | null
          stage_1_data: Json | null
          stage_2_data: Json | null
          stage_3_data: Json | null
          stage_4_data: Json | null
          stage_5_data: Json | null
          stage_6_data: Json | null
          stage_completion_criteria: Json | null
          stage_start_date: string
          supervising_physician_id: string
          symptoms_present: Json | null
          updated_at: string | null
        }
        Insert: {
          assessment_id: string
          athlete_id: string
          created_at?: string | null
          current_stage?: number
          final_clearance_date?: string | null
          id?: string
          injury_id?: string | null
          medical_clearances?: Json | null
          progression_notes?: string | null
          protocol_start_date?: string
          protocol_status?: string | null
          return_to_competition_date?: string | null
          setbacks?: Json | null
          stage_0_data?: Json | null
          stage_1_data?: Json | null
          stage_2_data?: Json | null
          stage_3_data?: Json | null
          stage_4_data?: Json | null
          stage_5_data?: Json | null
          stage_6_data?: Json | null
          stage_completion_criteria?: Json | null
          stage_start_date?: string
          supervising_physician_id: string
          symptoms_present?: Json | null
          updated_at?: string | null
        }
        Update: {
          assessment_id?: string
          athlete_id?: string
          created_at?: string | null
          current_stage?: number
          final_clearance_date?: string | null
          id?: string
          injury_id?: string | null
          medical_clearances?: Json | null
          progression_notes?: string | null
          protocol_start_date?: string
          protocol_status?: string | null
          return_to_competition_date?: string | null
          setbacks?: Json | null
          stage_0_data?: Json | null
          stage_1_data?: Json | null
          stage_2_data?: Json | null
          stage_3_data?: Json | null
          stage_4_data?: Json | null
          stage_5_data?: Json | null
          stage_6_data?: Json | null
          stage_completion_criteria?: Json | null
          stage_start_date?: string
          supervising_physician_id?: string
          symptoms_present?: Json | null
          updated_at?: string | null
        }
        Relationships: []
      }
      scat6_assessments: {
        Row: {
          assessment_date: string
          assessment_id: string
          assessor_name: string
          athlete_name: string
          cognitive_assessment: Json | null
          cognitive_screening: Json | null
          created_at: string | null
          delayed_recall: Json | null
          id: string
          injury_details: Json | null
          neurological_exam: Json | null
          neurological_screening: Json | null
          observable_signs: Json | null
          overall_rating: number | null
          recommendation: string
          red_flags: Json | null
          symptom_evaluation: Json | null
          symptom_severity: number | null
          total_symptom_score: number | null
          updated_at: string | null
        }
        Insert: {
          assessment_date: string
          assessment_id: string
          assessor_name: string
          athlete_name: string
          cognitive_assessment?: Json | null
          cognitive_screening?: Json | null
          created_at?: string | null
          delayed_recall?: Json | null
          id?: string
          injury_details?: Json | null
          neurological_exam?: Json | null
          neurological_screening?: Json | null
          observable_signs?: Json | null
          overall_rating?: number | null
          recommendation: string
          red_flags?: Json | null
          symptom_evaluation?: Json | null
          symptom_severity?: number | null
          total_symptom_score?: number | null
          updated_at?: string | null
        }
        Update: {
          assessment_date?: string
          assessment_id?: string
          assessor_name?: string
          athlete_name?: string
          cognitive_assessment?: Json | null
          cognitive_screening?: Json | null
          created_at?: string | null
          delayed_recall?: Json | null
          id?: string
          injury_details?: Json | null
          neurological_exam?: Json | null
          neurological_screening?: Json | null
          observable_signs?: Json | null
          overall_rating?: number | null
          recommendation?: string
          red_flags?: Json | null
          symptom_evaluation?: Json | null
          symptom_severity?: number | null
          total_symptom_score?: number | null
          updated_at?: string | null
        }
        Relationships: []
      }
      security_audit_logs: {
        Row: {
          action_type: string
          details: Json | null
          id: number
          ip_address: unknown | null
          location_data: Json | null
          resource_id: string | null
          resource_type: string | null
          risk_level: string | null
          session_id: string | null
          timestamp: string | null
          user_agent: string | null
          user_id: string | null
        }
        Insert: {
          action_type: string
          details?: Json | null
          id?: number
          ip_address?: unknown | null
          location_data?: Json | null
          resource_id?: string | null
          resource_type?: string | null
          risk_level?: string | null
          session_id?: string | null
          timestamp?: string | null
          user_agent?: string | null
          user_id?: string | null
        }
        Update: {
          action_type?: string
          details?: Json | null
          id?: number
          ip_address?: unknown | null
          location_data?: Json | null
          resource_id?: string | null
          resource_type?: string | null
          risk_level?: string | null
          session_id?: string | null
          timestamp?: string | null
          user_agent?: string | null
          user_id?: string | null
        }
        Relationships: []
      }
      standardized_tests: {
        Row: {
          created_at: string | null
          id: string
          interpretation: string | null
          koos_daily_living_score: number | null
          koos_pain_score: number | null
          koos_quality_of_life_score: number | null
          koos_sports_score: number | null
          koos_symptoms_score: number | null
          koos_total_score: number | null
          other_test_results: Json | null
          player_id: string
          test_date: string
          test_name: string
          tested_by: string | null
        }
        Insert: {
          created_at?: string | null
          id?: string
          interpretation?: string | null
          koos_daily_living_score?: number | null
          koos_pain_score?: number | null
          koos_quality_of_life_score?: number | null
          koos_sports_score?: number | null
          koos_symptoms_score?: number | null
          koos_total_score?: number | null
          other_test_results?: Json | null
          player_id: string
          test_date: string
          test_name: string
          tested_by?: string | null
        }
        Update: {
          created_at?: string | null
          id?: string
          interpretation?: string | null
          koos_daily_living_score?: number | null
          koos_pain_score?: number | null
          koos_quality_of_life_score?: number | null
          koos_sports_score?: number | null
          koos_symptoms_score?: number | null
          koos_total_score?: number | null
          other_test_results?: Json | null
          player_id?: string
          test_date?: string
          test_name?: string
          tested_by?: string | null
        }
        Relationships: []
      }
      system_settings: {
        Row: {
          created_at: string | null
          created_by: string | null
          description: string | null
          id: string
          is_encrypted: boolean | null
          setting_key: string
          setting_type: string | null
          setting_value: Json
          updated_at: string | null
        }
        Insert: {
          created_at?: string | null
          created_by?: string | null
          description?: string | null
          id?: string
          is_encrypted?: boolean | null
          setting_key: string
          setting_type?: string | null
          setting_value: Json
          updated_at?: string | null
        }
        Update: {
          created_at?: string | null
          created_by?: string | null
          description?: string | null
          id?: string
          is_encrypted?: boolean | null
          setting_key?: string
          setting_type?: string | null
          setting_value?: Json
          updated_at?: string | null
        }
        Relationships: []
      }
      training_programs: {
        Row: {
          created_at: string | null
          created_by: string | null
          end_date: string | null
          exercises: Json | null
          goals: string | null
          id: string
          player_id: string
          program_name: string
          program_type: string | null
          progress_notes: string | null
          start_date: string | null
          status: string | null
          updated_at: string | null
          weekly_schedule: Json | null
        }
        Insert: {
          created_at?: string | null
          created_by?: string | null
          end_date?: string | null
          exercises?: Json | null
          goals?: string | null
          id?: string
          player_id: string
          program_name: string
          program_type?: string | null
          progress_notes?: string | null
          start_date?: string | null
          status?: string | null
          updated_at?: string | null
          weekly_schedule?: Json | null
        }
        Update: {
          created_at?: string | null
          created_by?: string | null
          end_date?: string | null
          exercises?: Json | null
          goals?: string | null
          id?: string
          player_id?: string
          program_name?: string
          program_type?: string | null
          progress_notes?: string | null
          start_date?: string | null
          status?: string | null
          updated_at?: string | null
          weekly_schedule?: Json | null
        }
        Relationships: []
      }
      translations: {
        Row: {
          approved_at: string | null
          context: Json | null
          id: number
          language_code: string
          medical_terminology: boolean | null
          namespace: string
          reviewed_by: string | null
          translation_key: string
          translation_value: string
          version: number | null
        }
        Insert: {
          approved_at?: string | null
          context?: Json | null
          id?: number
          language_code: string
          medical_terminology?: boolean | null
          namespace: string
          reviewed_by?: string | null
          translation_key: string
          translation_value: string
          version?: number | null
        }
        Update: {
          approved_at?: string | null
          context?: Json | null
          id?: number
          language_code?: string
          medical_terminology?: boolean | null
          namespace?: string
          reviewed_by?: string | null
          translation_key?: string
          translation_value?: string
          version?: number | null
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      get_user_id: {
        Args: Record<PropertyKey, never>
        Returns: string
      }
      get_user_role: {
        Args: Record<PropertyKey, never>
        Returns: string
      }
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {},
  },
} as const
